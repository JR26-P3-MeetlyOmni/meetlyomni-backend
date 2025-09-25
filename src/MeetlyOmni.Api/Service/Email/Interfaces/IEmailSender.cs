// <copyright file="IEmailSender.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Email;

namespace MeetlyOmni.Api.Service.Email.Interfaces;

public interface IEmailSender
{
    Task<string> SendAsync(EmailMessage message, CancellationToken ct = default);
}
