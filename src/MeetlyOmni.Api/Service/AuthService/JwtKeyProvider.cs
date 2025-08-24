// <copyright file="JwtKeyProvider.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;

using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

public class JwtKeyProvider : IJwtKeyProvider
{
    private readonly SecurityKey _signingKey;

    public JwtKeyProvider()
    {
        // In production Azure Key Vault, AWS Secrets Manager, or env variable
        _signingKey = GenerateSecureKey();
    }

    public SecurityKey GetSigningKey() => _signingKey;

    public SecurityKey GetValidationKey() => _signingKey;

    private static SecurityKey GenerateSecureKey()
    {
        // random key
        using var rng = RandomNumberGenerator.Create();
        var keyBytes = new byte[32];
        rng.GetBytes(keyBytes);
        return new SymmetricSecurityKey(keyBytes);
    }
}
