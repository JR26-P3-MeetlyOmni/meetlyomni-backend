// <copyright file="TokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
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
    private readonly UserManager<Member> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    private readonly JwtOptions _jwtOptions;
    private readonly SigningCredentials _signingCredentials;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();
    private readonly ILogger<TokenService> _logger;

    // Token settings
    private const int RefreshTokenExpirationDays = 30;
    private const int RefreshTokenLength = 32;

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
        Guid? familyId = null)
    {
        var accessToken = await GenerateAccessTokenAsync(user);
        var accessTokenExpires = DateTimeOffset.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        // Generate refresh token
        var tokenFamilyId = familyId ?? Guid.NewGuid();
        var refreshTokenValue = GenerateRandomToken();
        var refreshTokenHash = ComputeHash(refreshTokenValue);
        var refreshTokenExpires = DateTimeOffset.UtcNow.AddDays(RefreshTokenExpirationDays);

        // Store refresh token
        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            FamilyId = tokenFamilyId,
            ExpiresAt = refreshTokenExpires,
            CreatedAt = DateTimeOffset.UtcNow,
            UserAgent = userAgent,
            IpAddress = ipAddress,
        };

        // Add to repository and save atomically
        _unitOfWork.RefreshTokens.Add(refreshToken);
        await _unitOfWork.SaveChangesAsync();

        return new TokenResult(
            accessToken,
            accessTokenExpires,
            refreshTokenValue,
            refreshTokenExpires);
    }

    public async Task<string> GenerateAccessTokenAsync(Member user)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        // Add org id
        if (user.OrgId != Guid.Empty)
        {
            claims.Add(new Claim("org_id", user.OrgId.ToString()));
        }

        // Get user claims and roles asynchronously
        var (userClaims, userRoles) = await GetUserClaimsAndRolesAsync(user);

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
        string ipAddress)
    {
        var tokenHash = ComputeHash(refreshToken);
        var storedToken = await _unitOfWork.RefreshTokens.FindByHashAsync(tokenHash);

        if (storedToken == null)
        {
            _logger.LogWarning("Refresh token not found: {TokenHash}", tokenHash[..8]);
            throw new UnauthorizedAccessException("Invalid refresh token.");
        }

        // Check for reuse attack - if token was already replaced
        if (storedToken.IsReplaced)
        {
            _logger.LogWarning(
                "Refresh token reuse detected for user {UserId}, family {FamilyId}",
                storedToken.UserId,
                storedToken.FamilyId);

            // Revoke all tokens in this family and save
            var revokedCount = await _unitOfWork.RefreshTokens.MarkTokenFamilyAsRevokedAsync(storedToken.FamilyId);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogWarning(
                "Revoked {Count} tokens in family {FamilyId} due to reuse detection",
                revokedCount,
                storedToken.FamilyId);
            throw new UnauthorizedAccessException("Token reuse detected. Please login again.");
        }

        // Check if token is expired or revoked
        if (!storedToken.IsActive)
        {
            _logger.LogWarning(
                "Inactive refresh token used for user {UserId}",
                storedToken.UserId);
            throw new UnauthorizedAccessException("Refresh token is expired or revoked.");
        }

        // Use transaction to ensure atomicity
        await _unitOfWork.BeginTransactionAsync();

        try
        {
            // Generate new tokens (this will add new token to context)
            var newTokens = await GenerateTokenPairAsync(
                storedToken.User,
                userAgent,
                ipAddress,
                storedToken.FamilyId);

            // Mark old token as replaced
            var newTokenHash = ComputeHash(newTokens.refreshToken);
            storedToken.RevokedAt = DateTimeOffset.UtcNow;
            storedToken.ReplacedByHash = newTokenHash;
            _unitOfWork.RefreshTokens.Update(storedToken);

            // Commit all changes atomically
            await _unitOfWork.CommitTransactionAsync();

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

    private async Task<(IList<Claim> claims, IList<string> roles)> GetUserClaimsAndRolesAsync(Member member)
    {
        // Get user claims and roles sequentially to avoid DbContext concurrency issues
        var userClaims = await _userManager.GetClaimsAsync(member);
        var userRoles = await _userManager.GetRolesAsync(member);

        return (userClaims, userRoles);
    }

    private static void AddUserClaims(List<Claim> claims, IList<Claim> userClaims)
    {
        // Map special claims to standard types
        var fullName = userClaims.FirstOrDefault(c => c.Type == "full_name")?.Value;
        if (!string.IsNullOrWhiteSpace(fullName))
        {
            claims.Add(new Claim(ClaimTypes.GivenName, fullName));
        }

        // Add other user claims (excluding processed ones)
        var excludedClaimTypes = new HashSet<string> { "full_name" };

        foreach (var claim in userClaims.Where(c => !excludedClaimTypes.Contains(c.Type)))
        {
            claims.Add(claim);
        }
    }

    private static void AddRoleClaims(List<Claim> claims, IList<string> userRoles)
    {
        foreach (var role in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
    }

    private static string GenerateRandomToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[RefreshTokenLength];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashedBytes).ToLowerInvariant();
    }
}
