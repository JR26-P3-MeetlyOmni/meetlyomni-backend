// <copyright file="EmailLinkService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;
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
}
