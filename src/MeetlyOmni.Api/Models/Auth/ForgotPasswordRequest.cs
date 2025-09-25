// <copyright file="ForgotPasswordRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Auth;

public sealed class ForgotPasswordRequest
{
    /// <summary>
    /// Gets email address to send password reset link to.
    /// </summary>
    [Required]
    [EmailAddress]
    public required string Email { get; init; }
}
