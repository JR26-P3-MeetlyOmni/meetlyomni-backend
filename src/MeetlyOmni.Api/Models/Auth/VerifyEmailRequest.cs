// <copyright file="VerifyEmailRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Auth;

public sealed class VerifyEmailRequest
{
    [Required]
    public required string Token { get; init; }

    [Required]
    [EmailAddress]
    public required string Email { get; init; }
}
