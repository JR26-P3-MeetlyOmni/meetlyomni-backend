// <copyright file="JwtTokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

public class JwtTokenService : IJwtTokenService
{
    private readonly UserManager<Member> _userManager;
    private readonly JwtOptions _jwtOptions;
    private readonly SigningCredentials _creds;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    public JwtTokenService(IOptions<JwtOptions> opt, UserManager<Member> userManager, IJwtKeyProvider keyProvider)
    {
        _userManager = userManager;
        _jwtOptions = opt.Value;
        var key = keyProvider.GetSigningKey();
        _creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    public async Task<TokenResult> GenerateTokenAsync(Member member)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, member.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, member.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        // org id
        if (member.OrgId != Guid.Empty)
        {
            claims.Add(new Claim("org_id", member.OrgId.ToString()));
        }

        // get user claims and roles
        var (userClaims, userRoles) = await GetUserClaimsAndRolesAsync(member);

        // add user custom claims
        AddUserClaims(claims, userClaims);

        // add role claims
        AddRoleClaims(claims, userRoles);

        // create JWT
        var jwt = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: _creds);

        var tokenString = _tokenHandler.WriteToken(jwt);
        return new TokenResult(tokenString, expires);
    }

    private static void AddUserClaims(List<Claim> claims, IList<Claim> userClaims)
    {
        // map special claims to standard types
        var fullName = userClaims.FirstOrDefault(c => c.Type == "full_name")?.Value;
        if (!string.IsNullOrWhiteSpace(fullName))
        {
            claims.Add(new Claim(ClaimTypes.GivenName, fullName));
        }

        // add other user claims (excluding processed ones)
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

    private async Task<(IList<Claim> claims, IList<string> roles)> GetUserClaimsAndRolesAsync(Member member)
    {
        // get user claims and roles
        var userClaimsTask = _userManager.GetClaimsAsync(member);
        var userRolesTask = _userManager.GetRolesAsync(member);

        await Task.WhenAll(userClaimsTask, userRolesTask);

        return (userClaimsTask.Result, userRolesTask.Result);
    }
}
