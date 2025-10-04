// <copyright file="ResetPasswordRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Auth;

public sealed class ResetPasswordRequest
{
    [Required]
    public required string Token { get; init; }

    [Required]
    [EmailAddress]
    public required string Email { get; init; }

    [Required]
    [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters long.")]
    public required string NewPassword { get; init; }

    [Required]
    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public required string ConfirmPassword { get; init; }
}
