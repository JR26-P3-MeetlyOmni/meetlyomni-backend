// <copyright file="JwtKeyProvider.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;

using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService;

/// <summary>
/// 统一的JWT密钥提供者，支持多种密钥来源.
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
        // 优先级：环境变量 > 配置文件 > 开发环境随机生成

        // 1. 尝试从环境变量获取（统一使用 JWT_SIGNING_KEY）
        var base64Key = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY");

        // 2. 尝试从配置获取（支持多个可能的键名以保持向后兼容）
        if (string.IsNullOrWhiteSpace(base64Key))
        {
            base64Key = config["Jwt:SigningKey"]
                     ?? config["Jwt:SigningKeyBase64"]
                     ?? config["JWT:SIGNING_KEY"];
        }

        // 3. 如果找到密钥，创建SecurityKey
        if (!string.IsNullOrWhiteSpace(base64Key))
        {
            try
            {
                var keyBytes = Convert.FromBase64String(base64Key);
                if (keyBytes.Length < 32) // 256 bits minimum for security
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

        // 4. 开发环境：生成随机密钥
        if (env.IsDevelopment())
        {
            return GenerateRandomKey();
        }

        // 5. 生产环境：必须配置密钥
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

        // 设置KeyId以支持密钥轮换
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(keyBytes);
        key.KeyId = Convert.ToBase64String(hash)[..8]; // 取前8个字符作为KeyId

        return key;
    }
}
