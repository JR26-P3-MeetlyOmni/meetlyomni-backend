// <copyright file="JwtTokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.JwtService;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

public class JwtTokenService : IJwtTokenService
{
    private readonly UserManager<Member> _userManager;
    private readonly JwtOptions _jwtOptions;
    private readonly SigningCredentials _creds;

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

        // use standard JWT Claims
        var claims = new List<Claim>
        {
            // standard Claims
            new(JwtRegisteredClaimNames.Sub, member.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, member.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Nbf, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, expires.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),

            // custom Claims - use standard ClaimTypes
            new(ClaimTypes.NameIdentifier, member.Id.ToString()),
            new(ClaimTypes.Email, member.Email ?? string.Empty),
        };

        // add org id (if needed)
        if (member.OrgId != Guid.Empty)
        {
            claims.Add(new Claim("org_id", member.OrgId.ToString()));
        }

        // batch get user Claims and Roles, reduce database calls
        var userClaimsTask = _userManager.GetClaimsAsync(member);
        var userRolesTask = _userManager.GetRolesAsync(member);

        await Task.WhenAll(userClaimsTask, userRolesTask);

        var userClaims = userClaimsTask.Result;
        var userRoles = userRolesTask.Result;

        // add user custom Claims
        var fullName = userClaims.FirstOrDefault(c => c.Type == "full_name")?.Value;
        if (!string.IsNullOrWhiteSpace(fullName))
        {
            claims.Add(new Claim(ClaimTypes.GivenName, fullName));
        }

        // add role Claims
        foreach (var role in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var jwt = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: _creds);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(jwt);
        return new TokenResult(tokenString, expires);
    }
}
