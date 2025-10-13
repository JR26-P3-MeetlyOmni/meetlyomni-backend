// <copyright file="TokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

/// <summary>
/// Service responsible for token generation and management.
/// </summary>
public class TokenService : ITokenService
{
    // Token settings
    private const int _refreshTokenLength = 32;

    private readonly UserManager<Member> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    private readonly JwtOptions _jwtOptions;
    private readonly SigningCredentials _signingCredentials;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();
    private readonly ILogger<TokenService> _logger;

    public TokenService(
        UserManager<Member> userManager,
        IUnitOfWork unitOfWork,
        IOptions<JwtOptions> jwtOptions,
        IJwtKeyProvider keyProvider,
        ILogger<TokenService> logger)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
        _jwtOptions = jwtOptions.Value;
        _logger = logger;

        var key = keyProvider.GetSigningKey();
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    public async Task<TokenResult> GenerateTokenPairAsync(
        Member user,
        string userAgent,
        string ipAddress,
        Guid? familyId = null,
        CancellationToken ct = default)
    {
        var accessToken = await GenerateAccessTokenAsync(user, ct);
        var accessTokenExpires = DateTimeOffset.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        // Generate refresh token
        var tokenFamilyId = familyId ?? Guid.NewGuid();
        var refreshTokenValue = GenerateRandomToken();
        var refreshTokenHash = ComputeHash(refreshTokenValue);

        // Calculate family expiration time (prevents infinite renewal)
        var now = DateTimeOffset.UtcNow;
        var familyExpiresAt = familyId == null
            ? now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes) // New family: set max lifetime
            : await GetFamilyExpirationTimeAsync(tokenFamilyId, ct); // Existing family: use existing max lifetime

        // Calculate individual token expiration (respects family limit)
        var individualExpiresAt = now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes);
        var refreshTokenExpires = individualExpiresAt < familyExpiresAt
            ? individualExpiresAt
            : familyExpiresAt;

        // Sanitize inputs to respect database constraints
        var ua = (userAgent ?? string.Empty).Trim();
        var ip = (ipAddress ?? string.Empty).Trim();
        if (ua.Length > 500)
        {
            ua = ua[..500];
        }

        if (ip.Length > 45)
        {
            ip = ip[..45];
        }

        // Store refresh token
        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            FamilyId = tokenFamilyId,
            ExpiresAt = refreshTokenExpires,
            FamilyExpiresAt = familyExpiresAt,
            CreatedAt = now,
            UserAgent = ua,
            IpAddress = ip,
        };

        // Add to repository and save atomically
        _unitOfWork.RefreshTokens.Add(refreshToken);
        await _unitOfWork.SaveChangesAsync(ct);

        return new TokenResult(
            accessToken,
            accessTokenExpires,
            refreshTokenValue,
            refreshTokenExpires);
    }

    public async Task<string> GenerateAccessTokenAsync(Member user, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new("name", user.UserName ?? string.Empty), // Short claim name
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        // Add org id
        if (user.OrgId != Guid.Empty)
        {
            claims.Add(new Claim("org_id", user.OrgId.ToString()));
        }

        // Get user claims and roles asynchronously
        var (userClaims, userRoles) = await GetUserClaimsAndRolesAsync(user, ct);

        // Add user custom claims
        AddUserClaims(claims, userClaims);

        // Add role claims
        AddRoleClaims(claims, userRoles);

        // Create JWT
        var jwt = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: _signingCredentials);

        return _tokenHandler.WriteToken(jwt);
    }

    public async Task<TokenResult> RefreshTokenPairAsync(
        string refreshToken,
        string userAgent,
        string ipAddress,
        CancellationToken ct = default)
    {
        var tokenHash = ComputeHash(refreshToken);
        var storedToken = await _unitOfWork.RefreshTokens.FindByHashAsync(tokenHash, ct);

        if (storedToken == null)
        {
            _logger.LogWarning("Refresh token not found: {TokenHash}", tokenHash[..8]);
            throw new UnauthorizedAppException("Invalid refresh token.");
        }

        // Check for reuse attack - if token was already replaced
        if (storedToken.IsReplaced)
        {
            _logger.LogWarning(
                "Refresh token reuse detected for user {UserId}, family {FamilyId}",
                storedToken.UserId,
                storedToken.FamilyId);

            // Revoke all tokens in this family and save
            var revokedCount = await _unitOfWork.RefreshTokens.MarkTokenFamilyAsRevokedAsync(storedToken.FamilyId, ct);
            await _unitOfWork.SaveChangesAsync(ct);

            _logger.LogWarning(
                "Revoked {Count} tokens in family {FamilyId} due to reuse detection",
                revokedCount,
                storedToken.FamilyId);
            throw new UnauthorizedAppException("Token reuse detected. Please login again.");
        }

        // Check if token is expired or revoked
        if (!storedToken.IsActive)
        {
            _logger.LogWarning(
                "Inactive refresh token used for user {UserId}",
                storedToken.UserId);
            throw new UnauthorizedAppException("Refresh token is expired or revoked.");
        }

        // Use transaction to ensure atomicity
        await _unitOfWork.BeginTransactionAsync(ct);

        try
        {
            // Generate new tokens (this will add new token to context)
            var newTokens = await GenerateTokenPairAsync(
                storedToken.User,
                userAgent,
                ipAddress,
                storedToken.FamilyId,
                ct);

            // Atomically mark old token as replaced only if still active and not replaced
            var newTokenHash = ComputeHash(newTokens.refreshToken);
            var affected = await _unitOfWork.RefreshTokens
                .MarkSingleTokenAsReplacedAsync(storedToken.Id, newTokenHash, ct);
            if (affected == 0)
            {
                await _unitOfWork.RollbackTransactionAsync();
                throw new UnauthorizedAppException("Refresh token already used.");
            }

            // Commit all changes atomically
            await _unitOfWork.CommitTransactionAsync(ct);

            _logger.LogInformation(
                "Successfully refreshed tokens for user {UserId}",
                storedToken.UserId);

            return newTokens;
        }
        catch
        {
            await _unitOfWork.RollbackTransactionAsync();
            throw;
        }
    }

    public async Task<TokenResult> RefreshTokenPairFromCookiesAsync(
        HttpContext httpContext,
        string userAgent,
        string ipAddress,
        CancellationToken ct = default)
    {
        // Extract refresh token from cookies
        if (!httpContext.Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
            string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new UnauthorizedAppException("Refresh token is missing.");
        }

        // Delegate to the existing method
        return await RefreshTokenPairAsync(refreshToken, userAgent, ipAddress, ct);
    }

    private static void AddUserClaims(List<Claim> claims, IList<Claim> userClaims)
    {
        // Add all user custom claims directly
        foreach (var claim in userClaims)
        {
            claims.Add(claim);
        }
    }

    private static void AddRoleClaims(List<Claim> claims, IList<string> userRoles)
    {
        foreach (var role in userRoles)
        {
            claims.Add(new Claim("role", role)); // Short claim name
        }
    }

    private static string GenerateRandomToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[_refreshTokenLength];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashedBytes).ToLowerInvariant();
    }

    private async Task<(IList<Claim> claims, IList<string> roles)> GetUserClaimsAndRolesAsync(Member member, CancellationToken ct = default)
    {
        // Get user claims and roles sequentially to avoid DbContext concurrency issues
        // Note: UserManager methods don't support CancellationToken, so we can't pass it through
        var userClaims = await _userManager.GetClaimsAsync(member);
        var userRoles = await _userManager.GetRolesAsync(member);

        return (userClaims, userRoles);
    }

    private async Task<DateTimeOffset> GetFamilyExpirationTimeAsync(Guid familyId, CancellationToken ct)
    {
        // Get the family expiration time from any existing token in the family
        var existingToken = await _unitOfWork.RefreshTokens.FindByFamilyIdAsync(familyId, ct);
        return existingToken?.FamilyExpiresAt ?? DateTimeOffset.UtcNow.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes);
    }

    public async Task<LoginResponse> GenerateTokensAsync(Member user, CancellationToken ct = default)
    {
        var accessTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        return new LoginResponse
        {
            ExpiresAt = accessTokenExpiresAt,
            TokenType = "Bearer",
        };
    }
}
