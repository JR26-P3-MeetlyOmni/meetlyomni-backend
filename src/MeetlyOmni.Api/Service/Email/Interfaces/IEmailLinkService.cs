// <copyright file="IEmailLinkService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Service.Email.Interfaces;

public interface IEmailLinkService
{
    Task<string> GeneratePasswordResetLinkAsync(Member user, CancellationToken ct = default);

    Task<string> GenerateEmailVerificationLinkAsync(Member user, CancellationToken ct = default);

    Task<bool> ValidatePasswordResetTokenAsync(string email, string token, CancellationToken ct = default);

    Task<bool> ValidateEmailVerificationTokenAsync(string email, string token, CancellationToken ct = default);

    Task<bool> ValidateAndConfirmEmailAsync(string email, string token, CancellationToken ct = default);
}
