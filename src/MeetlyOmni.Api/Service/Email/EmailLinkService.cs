// <copyright file="EmailLinkService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.Email.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace MeetlyOmni.Api.Service.Email;

public sealed class EmailLinkService : IEmailLinkService
{
    private readonly UserManager<Member> _userManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailLinkService> _logger;

    public EmailLinkService(
        UserManager<Member> userManager,
        IConfiguration configuration,
        ILogger<EmailLinkService> logger)
    {
        _userManager = userManager;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<string> GeneratePasswordResetLinkAsync(Member user, CancellationToken ct = default)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        var apiBase = _configuration["Backend:ApiBaseUrl"];
        var userId = user.Id.ToString();
        var email = user.Email ?? string.Empty;

        var link =
            $"{apiBase}/auth/direct2-reset" +
            $"?userId={Uri.EscapeDataString(userId)}" +
            $"&token={encodedToken}" +
            $"&email={Uri.EscapeDataString(email)}";

        return link;
    }

    public async Task<string> GenerateEmailVerificationLinkAsync(Member user, CancellationToken ct = default)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        var apiBase = _configuration["Backend:ApiBaseUrl"];
        var userId = user.Id.ToString();
        var email = user.Email ?? string.Empty;

        var link =
            $"{apiBase}/auth/verify-email" +
            $"?userId={Uri.EscapeDataString(userId)}" +
            $"&token={encodedToken}" +
            $"&email={Uri.EscapeDataString(email)}";

        return link;
    }

    public async Task<bool> ValidatePasswordResetTokenAsync(string email, string token, CancellationToken ct = default)
    {
        return await ValidateTokenAsync(
            email,
            token,
            _userManager.Options.Tokens.PasswordResetTokenProvider,
            "ResetPassword",
            "password reset");
    }

    public async Task<bool> ValidateEmailVerificationTokenAsync(string email, string token, CancellationToken ct = default)
    {
        return await ValidateTokenAsync(
            email,
            token,
            _userManager.Options.Tokens.EmailConfirmationTokenProvider,
            "EmailConfirmation",
            "email verification");
    }

    public async Task<bool> ValidateAndConfirmEmailAsync(string email, string token, CancellationToken ct = default)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return false;
        }

        if (user.EmailConfirmed)
        {
            return true; // Already confirmed, consider it success
        }

        var normalizedToken = HttpUtility.UrlDecode(token) ?? token;
        var result = await _userManager.ConfirmEmailAsync(user, normalizedToken);

        return result.Succeeded;
    }

    /// <summary>
    /// Common method to validate user tokens.
    /// </summary>
    private async Task<bool> ValidateTokenAsync(string email, string token, string tokenProvider, string purpose, string operationType)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return false;
        }

        var normalizedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        var isValid = await _userManager.VerifyUserTokenAsync(user, tokenProvider, purpose, normalizedToken);

        return isValid;
    }

    public async Task<string> GenerateInvitationTokenAsync(string email, Guid orgId, CancellationToken ct = default)
    {
        // Create a custom token for invitation
        var tokenData = new
        {
            Email = email,
            OrgId = orgId,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds(),
            Type = "Invitation",
        };

        var jsonData = JsonSerializer.Serialize(tokenData);
        var dataBytes = Encoding.UTF8.GetBytes(jsonData);

        // Use HMAC for signing
        var key = _configuration["Jwt:SecretKey"] ?? "default-secret-key";
        var keyBytes = Encoding.UTF8.GetBytes(key);

        using var hmac = new HMACSHA256(keyBytes);
        var signature = hmac.ComputeHash(dataBytes);

        var token = Convert.ToBase64String(dataBytes) + "." + Convert.ToBase64String(signature);
        return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
    }

    public async Task<bool> ValidateInvitationTokenAsync(string email, string token, CancellationToken ct = default)
    {
        try
        {
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var parts = decodedToken.Split('.');

            if (parts.Length != 2)
            {
                return false;
            }

            var dataBytes = Convert.FromBase64String(parts[0]);
            var signature = Convert.FromBase64String(parts[1]);

            // Verify signature
            var key = _configuration["Jwt:SecretKey"] ?? "default-secret-key";
            var keyBytes = Encoding.UTF8.GetBytes(key);

            using var hmac = new HMACSHA256(keyBytes);
            var expectedSignature = hmac.ComputeHash(dataBytes);

            if (!signature.SequenceEqual(expectedSignature))
            {
                return false;
            }

            // Parse token data
            var jsonData = Encoding.UTF8.GetString(dataBytes);
            var tokenData = JsonSerializer.Deserialize<JsonElement>(jsonData);

            // Check if token is for invitation
            if (!tokenData.TryGetProperty("Type", out var type) || type.GetString() != "Invitation")
            {
                return false;
            }

            // Check email match
            if (!tokenData.TryGetProperty("Email", out var tokenEmail) || tokenEmail.GetString() != email)
            {
                return false;
            }

            // Check expiration
            if (tokenData.TryGetProperty("ExpiresAt", out var expiresAt))
            {
                var expirationTime = DateTimeOffset.FromUnixTimeSeconds(expiresAt.GetInt64());
                if (expirationTime < DateTimeOffset.UtcNow)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate invitation token for {Email}", email);
            return false;
        }
    }

    public async Task<Guid?> GetOrganizationIdFromInvitationTokenAsync(string token, CancellationToken ct = default)
    {
        try
        {
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var parts = decodedToken.Split('.');

            if (parts.Length != 2)
            {
                return null;
            }

            var dataBytes = Convert.FromBase64String(parts[0]);
            var jsonData = Encoding.UTF8.GetString(dataBytes);
            var tokenData = JsonSerializer.Deserialize<JsonElement>(jsonData);

            if (tokenData.TryGetProperty("OrgId", out var orgId))
            {
                return Guid.Parse(orgId.GetString()!);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get organization ID from invitation token");
            return null;
        }
    }

    public string GetBaseUrl()
    {
        return _configuration["Frontend:BaseUrl"] ?? "http://localhost:3000";
    }
}
