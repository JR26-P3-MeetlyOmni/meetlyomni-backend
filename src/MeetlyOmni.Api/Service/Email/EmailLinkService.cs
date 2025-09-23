// <copyright file="EmailLinkService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;
using System.Web;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.Email.Interfaces;

using Microsoft.AspNetCore.Identity;

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
        // Generate secure token using ASP.NET Core Identity
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        var encodedToken = HttpUtility.UrlEncode(token);
        var encodedEmail = HttpUtility.UrlEncode(user.Email ?? string.Empty);

        var frontendUrl = _configuration["Frontend:BaseUrl"] ?? "http://localhost:3000";

        var resetLink = $"{frontendUrl}/auth/reset-password?token={encodedToken}&email={encodedEmail}";

        _logger.LogInformation("Generated password reset link for user {UserId}", user.Id);

        return resetLink;
    }

    public async Task<string> GenerateEmailVerificationLinkAsync(Member user, CancellationToken ct = default)
    {
        // Generate secure token using ASP.NET Core Identity
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var encodedToken = HttpUtility.UrlEncode(token);
        var encodedEmail = HttpUtility.UrlEncode(user.Email ?? string.Empty);

        var frontendUrl = _configuration["Frontend:BaseUrl"] ?? "http://localhost:3000";

        var verifyLink = $"{frontendUrl}/auth/verify-email?token={encodedToken}&email={encodedEmail}";

        _logger.LogInformation("Generated email verification link for user {UserId}", user.Id);

        return verifyLink;
    }

    public async Task<bool> ValidatePasswordResetTokenAsync(string email, string token, CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("Validating password reset token for {Email}", email);

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("Password reset validation failed: user not found for {Email}", email);
                return false;
            }

            var isValid = await _userManager.VerifyUserTokenAsync(
                user,
                _userManager.Options.Tokens.PasswordResetTokenProvider,
                "ResetPassword",
                token);

            _logger.LogInformation("Password reset token validation result for {Email}: {IsValid}", email, isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating password reset token for {Email}", email);
            return false;
        }
    }

    public async Task<bool> ValidateAndConfirmEmailAsync(string email, string token, CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("Validating and confirming email for {Email}", email);

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("Email verification failed: user not found for {Email}", email);
                return false;
            }

            if (user.EmailConfirmed)
            {
                _logger.LogInformation("Email already confirmed for {Email}", email);
                return true; // Already confirmed, consider it success
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                _logger.LogInformation("Email successfully confirmed for {Email}", email);
                return true;
            }
            else
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Email confirmation failed for {Email}: {Errors}", email, errors);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating email verification token for {Email}", email);
            return false;
        }
    }

    public async Task<bool> ResetPasswordAsync(string email, string token, string newPassword, CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("Attempting password reset for {Email}", email);

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("Password reset failed: user not found for {Email}", email);
                return false;
            }

            // Reset the password using the token
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password successfully reset for {Email}", email);
                return true;
            }
            else
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Password reset failed for {Email}: {Errors}", email, errors);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for {Email}", email);
            return false;
        }
    }
}
