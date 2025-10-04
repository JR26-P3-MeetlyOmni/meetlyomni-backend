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
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public async Task<string> SendResetPasswordAsync(Member user, CancellationToken ct = default) =>
        await SendEmailWithLinkAsync(
            user,
            EmailType.ResetPassword,
            "resetLink",
            user => _linkService.GeneratePasswordResetLinkAsync(user, ct),
            ct);

    /// <summary>
    /// Send email verification with secure token-based link.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public async Task<string> SendVerifyEmailAsync(Member user, CancellationToken ct = default) =>
        await SendEmailWithLinkAsync(
            user,
            EmailType.VerifyEmail,
            "verifyLink",
            user => _linkService.GenerateEmailVerificationLinkAsync(user, ct),
            ct);

    /// <summary>
    /// Send email with token-based link using common pattern.
    /// </summary>
    private async Task<string> SendEmailWithLinkAsync(
        Member user,
        EmailType emailType,
        string linkKey,
        Func<Member, Task<string>> linkGenerator,
        CancellationToken ct)
    {
        if (user is null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            throw new ArgumentException("User email is required to send email.", nameof(user));
        }

        var link = await linkGenerator(user);
        var msg = _tpl.Build(
            emailType,
            user.Email,
            new Dictionary<string, string> { [linkKey] = link });
        return await _sender.SendAsync(msg, ct);
    }
}
