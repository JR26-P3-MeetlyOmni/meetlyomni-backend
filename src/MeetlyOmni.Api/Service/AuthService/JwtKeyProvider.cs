// <copyright file="JwtKeyProvider.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Buffers.Text;
using System.Security.Cryptography;

using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

public class JwtKeyProvider : IJwtKeyProvider
{
    private readonly SecurityKey _signingKey;

    public JwtKeyProvider(IConfiguration config, IHostEnvironment env)
    {
        // Prefer configured key; fall back to dev-only random key
        var base64 = config["Jwt:SigningKey"] ?? Environment.GetEnvironmentVariable("JWT__SIGNING_KEY");
        if (!string.IsNullOrWhiteSpace(base64))
        {
            var keyBytes = Convert.FromBase64String(base64);
            _signingKey = CreateSymmetricKey(keyBytes);
            return;
        }

        if (!env.IsDevelopment())
        {
            throw new InvalidOperationException("JWT signing key must be configured in non-development environments.");
        }

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
        return CreateSymmetricKey(keyBytes);
    }

    private static SecurityKey CreateSymmetricKey(byte[] keyBytes)
    {
        var key = new SymmetricSecurityKey(keyBytes);

        // Set a deterministic kid for rotation support (base64url of SHA-256)
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(keyBytes);
        key.KeyId = Base64UrlEncoder.Encode(hash);
        return key;
    }
}
