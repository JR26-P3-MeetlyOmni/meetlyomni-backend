// <copyright file="AcceptInvitationRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Invitation;

/// <summary>
/// Request model for accepting an invitation to join an organization.
/// </summary>
public class AcceptInvitationRequest
{
    /// <summary>
    /// Gets or sets email address of the user accepting the invitation.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets password for the new account.
    /// </summary>
    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets invitation token received via email.
    /// </summary>
    [Required]
    public string Token { get; set; } = string.Empty;
}
