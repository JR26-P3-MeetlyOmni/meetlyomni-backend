// <copyright file="EmailMessage.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Email;

public sealed class EmailMessage
{
    public required string To { get; init; }

    public required string Subject { get; init; }

    public required string HtmlBody { get; init; }

    public required string TextBody { get; init; }
}
