namespace MeetlyOmni.Api.Models.Auth;

public sealed class ConfirmEmailRequest
{
    public string UserId { get; set; } = default!;

    public string Code { get; set; } = default!;
}
