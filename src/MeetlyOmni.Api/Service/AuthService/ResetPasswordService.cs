// <copyright file="ResetPasswordService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text;
using System.Web;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

namespace MeetlyOmni.Api.Service.AuthService;

public sealed class ResetPasswordService : IResetPasswordService
{
    private readonly UserManager<Member> _userManager;
    private readonly ILogger<ResetPasswordService> _logger;

    public ResetPasswordService(
        UserManager<Member> userManager,
        ILogger<ResetPasswordService> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IdentityResult> ResetPasswordAsync(string email, string token, string newPassword, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(newPassword))
        {
            _logger.LogWarning("ResetPassword: invalid input (email/token/password missing)");
            return IdentityResult.Failed(new IdentityError
            {
                Code = "InvalidResetRequest",
                Description = "Invalid or expired token.",
            });
        }

        ct.ThrowIfCancellationRequested();
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "InvalidResetRequest",
                Description = "Invalid or expired token.",
            });
        }

        var normalizedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        var result = await _userManager.ResetPasswordAsync(user, normalizedToken, newPassword);

        if (result.Succeeded)
        {
            _logger.LogInformation("Password successfully reset for user {UserId}", user.Id);
            return result;
        }

        _logger.LogWarning(
            "Password reset failed for user {UserId}: {Errors}",
            user.Id,
            string.Join(", ", result.Errors.Select(e => e.Description)));
        return result;
    }
}
