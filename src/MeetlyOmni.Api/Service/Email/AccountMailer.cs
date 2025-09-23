// <copyright file="AccountMailer.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.EmailType;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.Email.Interfaces;

namespace MeetlyOmni.Api.Service.Email;

public sealed class AccountMailer
{
    private readonly IEmailTemplateService _tpl;
    private readonly IEmailSender _sender;
    private readonly IEmailLinkService _linkService;

    public AccountMailer(IEmailTemplateService tpl, IEmailSender sender, IEmailLinkService linkService)
    {
        _tpl = tpl;
        _sender = sender;
        _linkService = linkService;
    }

    /// <summary>
    /// Send password reset email with secure token-based link.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    public async Task<string> SendResetPasswordAsync(Member user, CancellationToken ct = default)
    {
        var resetLink = await _linkService.GeneratePasswordResetLinkAsync(user, ct);
        var msg = _tpl.Build(
            EmailType.ResetPassword,
            user.Email ?? string.Empty,
            new Dictionary<string, string> { ["resetLink"] = resetLink });
        return await _sender.SendAsync(msg, ct);
    }

    /// <summary>
    /// Send email verification with secure token-based link.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    public async Task<string> SendVerifyEmailAsync(Member user, CancellationToken ct = default)
    {
        var verifyLink = await _linkService.GenerateEmailVerificationLinkAsync(user, ct);
        var msg = _tpl.Build(
            EmailType.VerifyEmail,
            user.Email ?? string.Empty,
            new Dictionary<string, string> { ["verifyLink"] = verifyLink });
        return await _sender.SendAsync(msg, ct);
    }
}
