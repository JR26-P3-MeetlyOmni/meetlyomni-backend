// <copyright file="AwsSesEmailSender.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Amazon;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;

using MeetlyOmni.Api.Models.Email;
using MeetlyOmni.Api.Service.Email.Interfaces;

namespace MeetlyOmni.Api.Service.Email;
public sealed class AwsSesEmailSender : IEmailSender
{
    private readonly IAmazonSimpleEmailServiceV2 _ses;
    private readonly string _fromEmail;
    private readonly string _fromName;
    private readonly ILogger<AwsSesEmailSender> _logger;

    public AwsSesEmailSender(IConfiguration cfg, ILogger<AwsSesEmailSender> logger)
    {
        _logger = logger;
        _fromEmail = cfg["Ses:FromEmail"] ?? throw new ArgumentNullException("Ses:FromEmail");
        _fromName = cfg["Ses:FromName"] ?? "MeetlyOmni";

        // local variable/IAM role credentials - uses default credential chain
        var region = RegionEndpoint.GetBySystemName(cfg["Ses:Region"] ?? "ap-southeast-2");
        _ses = new AmazonSimpleEmailServiceV2Client(region);
    }

    public async Task<string> SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(message.To))
        {
            throw new ArgumentException("Recipient (To) must not be empty.", nameof(message));
        }

        var req = new SendEmailRequest
        {
            FromEmailAddress = $"{_fromName} <{_fromEmail}>",
            Destination = new Destination { ToAddresses = new List<string> { message.To } },
            Content = new EmailContent
            {
                Simple = new Message
                {
                    Subject = new Content { Data = message.Subject, Charset = "UTF-8" },
                    Body = new Body
                    {
                        Html = new Content { Data = message.HtmlBody, Charset = "UTF-8" },
                        Text = new Content { Data = message.TextBody, Charset = "UTF-8" },
                    },
                },
            },
        };

        try
        {
            var res = await _ses.SendEmailAsync(req, ct);
            _logger.LogDebug("SES email sent successfully. MessageId={MessageId}", res.MessageId);
            return res.MessageId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SES send failed. From={From}", req.FromEmailAddress);
            throw;
        }
    }
}
