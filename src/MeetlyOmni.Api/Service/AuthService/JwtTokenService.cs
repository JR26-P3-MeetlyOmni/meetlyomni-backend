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

        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Sub, member.Id.ToString()),
            new (JwtRegisteredClaimNames.Email, member.Email ?? string.Empty),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new (JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new ("org_id", member.OrgId.ToString()),
        };

        // add full_name claim if available
        var userClaims = await _userManager.GetClaimsAsync(member);
        var fullName = userClaims.FirstOrDefault(c => c.Type == "full_name")?.Value;
        if (!string.IsNullOrWhiteSpace(fullName))
        {
            claims.Add(new Claim("full_name", fullName));
        }

        var roles = await _userManager.GetRolesAsync(member);
        foreach (var role in roles)
        {
            claims.Add(new Claim("role", role));
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
