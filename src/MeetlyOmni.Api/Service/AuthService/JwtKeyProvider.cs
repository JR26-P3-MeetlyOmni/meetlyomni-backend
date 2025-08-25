// <copyright file="JwtKeyProvider.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;

using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

/// <summary>
/// unified JWT key provider, supports multiple key sources.
/// </summary>
public class JwtKeyProvider : IJwtKeyProvider
{
    private readonly SecurityKey _signingKey;

    public JwtKeyProvider(IConfiguration config, IHostEnvironment env)
    {
        _signingKey = CreateSigningKey(config, env);
    }

    public SecurityKey GetSigningKey() => _signingKey;

    public SecurityKey GetValidationKey() => _signingKey;

    private static SecurityKey CreateSigningKey(IConfiguration config, IHostEnvironment env)
    {
        // priority: environment variable > configuration file > development environment random generation

        // 1. try to get from environment variable (use JWT_SIGNING_KEY)
        var base64Key = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY");

        // 2. try to get from configuration (support multiple possible key names to maintain backward compatibility)
        if (string.IsNullOrWhiteSpace(base64Key))
        {
            base64Key = config["Jwt:SigningKey"]
                     ?? config["Jwt:SigningKeyBase64"]
                     ?? config["JWT:SIGNING_KEY"];
        }

        // 3. if key is found, create SecurityKey
        if (!string.IsNullOrWhiteSpace(base64Key))
        {
            try
            {
                var keyBytes = Convert.FromBase64String(base64Key);

                // 256 bits minimum for security
                if (keyBytes.Length < 32)
                {
                    throw new InvalidOperationException($"JWT signing key must be at least 256 bits (32 bytes). Current key is {keyBytes.Length * 8} bits.");
                }

                return CreateSymmetricKey(keyBytes);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("JWT signing key is not a valid Base64 string.", ex);
            }
        }

        // 4. development environment: generate random key
        if (env.IsDevelopment())
        {
            return GenerateRandomKey();
        }

        // 5. production environment: must configure key
        throw new InvalidOperationException(
            "JWT signing key must be configured in non-development environments. " +
            "Set environment variable JWT_SIGNING_KEY or configuration key Jwt:SigningKey with a Base64-encoded key.");
    }

    private static SecurityKey GenerateRandomKey()
    {
        using var rng = RandomNumberGenerator.Create();
        var keyBytes = new byte[32]; // 256 bits
        rng.GetBytes(keyBytes);
        return CreateSymmetricKey(keyBytes);
    }

    private static SecurityKey CreateSymmetricKey(byte[] keyBytes)
    {
        var key = new SymmetricSecurityKey(keyBytes);

        // set KeyId to support key rotation
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(keyBytes);
        key.KeyId = Convert.ToBase64String(hash)[..8]; // take the first 8 characters as KeyId

        return key;
    }
}
