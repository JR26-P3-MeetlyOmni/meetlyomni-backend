using FluentEmail.Core;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;

namespace MeetlyOmni.Api.Service.EmailService;

public class EmailSender : IEmailSender
{
    private readonly IFluentEmail _email;
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(IFluentEmail email, ILogger<EmailSender> logger)
    {
        _email = email;
        _logger = logger;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("Email address cannot be null or empty.", nameof(email));
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentException("Subject cannot be null or empty.", nameof(subject));
        }

        if (string.IsNullOrWhiteSpace(htmlMessage))
        {
            throw new ArgumentException("Message content cannot be null or empty.", nameof(htmlMessage));
        }

        try
        {
            _logger.LogInformation("Sending email to {Email} with subject: {Subject}", email, subject);

            var resp = await _email
                .To(email)
                .Subject(subject)
                .Body(htmlMessage, isHtml: true)
                .SendAsync();

            if (!resp.Successful)
            {
                var errors = string.Join("; ", resp.ErrorMessages ?? new List<string>());
                _logger.LogError("Failed to send email to {Email}. Errors: {Errors}", email, errors);
                throw new InvalidOperationException($"Email send failed: {errors}");
            }

            _logger.LogInformation("Email sent successfully to {Email}", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while sending email to {Email}", email);
            throw;
        }
    }
}
