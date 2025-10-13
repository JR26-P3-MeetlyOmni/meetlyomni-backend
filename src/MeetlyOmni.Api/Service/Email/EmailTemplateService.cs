// <copyright file="EmailTemplateService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.EmailType;
using MeetlyOmni.Api.Models.Email;
using MeetlyOmni.Api.Service.Email.Interfaces;

namespace MeetlyOmni.Api.Service.Email;

public sealed class EmailTemplateService : IEmailTemplateService
{
    private readonly string _fromName;

    public EmailTemplateService(IConfiguration config)
    {
        _fromName = config["Ses:FromName"] ?? "MeetlyOmni";
    }

    public EmailMessage Build(EmailType type, string to, IDictionary<string, string> data)
    {
        return type switch
        {
            EmailType.ResetPassword => BuildResetPassword(to, data),
            EmailType.VerifyEmail => BuildVerifyEmail(to, data),
            EmailType.MemberInvitation => BuildMemberInvitation(to, data),
            _ => throw new NotSupportedException(type.ToString())
        };
    }

    private EmailMessage BuildResetPassword(string to, IDictionary<string, string> d)
    {
        var link = d["resetLink"];
        var subject = "Reset your password";
        var html = $@"
            <div style=""font-family:Segoe UI,Arial,sans-serif;font-size:14px"">
              <h2>Reset your password</h2>
              <p>Click the button below to reset your password:</p>
              <p><a href=""{link}"" 
                    style=""background:#4f46e5;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;"">
                    Reset Password
                  </a></p>
              <p>If you didn't request this, you can ignore this email.</p>
              <hr/><p style=""color:#777"">{_fromName}</p>
            </div>";

        var text = $@"Reset your password

Open the link to reset: {link}

If you didn't request this, ignore this email.
{_fromName}";

        return new EmailMessage { To = to, Subject = subject, HtmlBody = html, TextBody = text };
    }

    private EmailMessage BuildVerifyEmail(string to, IDictionary<string, string> d)
    {
        var link = d["verifyLink"];
        var subject = "Verify your email address";
        var html = $@"
            <div style=""font-family:Segoe UI,Arial,sans-serif;font-size:14px"">
              <h2>Verify your email</h2>
              <p>Thanks for signing up! Please confirm your email address:</p>
              <p><a href=""{link}""
                    style=""background:#16a34a;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;"">
                    Verify Email
                  </a></p>
              <p>This link will expire soon for your security.</p>
              <hr/><p style=""color:#777"">{_fromName}</p>
            </div>";

        var text = $@"Verify your email

Please open the link to verify: {link}

This link will expire soon.
{_fromName}";

        return new EmailMessage { To = to, Subject = subject, HtmlBody = html, TextBody = text };
    }

    private EmailMessage BuildMemberInvitation(string to, IDictionary<string, string> d)
    {
        var organizationName = d["organizationName"];
        var invitationLink = d["invitationLink"];
        var message = d["message"];

        var subject = $"You're invited to join {organizationName} on MeetlyOmni";
        var html = $@"
            <div style=""font-family:Segoe UI,Arial,sans-serif;font-size:14px"">
              <h2>You're invited to join {organizationName}!</h2>
              <p>You've been invited to join <strong>{organizationName}</strong> on MeetlyOmni.</p>
              {(string.IsNullOrEmpty(message) ? string.Empty : $"<p><em>Message: {message}</em></p>")}
              <p>Click the button below to accept the invitation and create your account:</p>
              <p><a href=""{invitationLink}""
                    style=""background:#4f46e5;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;"">
                    Accept Invitation
                  </a></p>
              <p>This invitation will expire in 7 days for security reasons.</p>
              <hr/><p style=""color:#777"">{_fromName}</p>
            </div>";

        var text = $@"You're invited to join {organizationName}!

You've been invited to join {organizationName} on MeetlyOmni.
{(string.IsNullOrEmpty(message) ? string.Empty : $"Message: {message}")}

Accept the invitation: {invitationLink}

This invitation will expire in 7 days.
{_fromName}";

        return new EmailMessage { To = to, Subject = subject, HtmlBody = html, TextBody = text };
    }
}
