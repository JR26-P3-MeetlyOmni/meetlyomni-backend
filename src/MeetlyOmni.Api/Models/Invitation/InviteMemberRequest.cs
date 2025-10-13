// <copyright file="InviteMemberRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Invitation;

/// <summary>
/// Request model for inviting a member to join an organization.
/// </summary>
public class InviteMemberRequest
{
    /// <summary>
    /// Gets or sets email address of the member to invite.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets optional message to include in the invitation email.
    /// </summary>
    public string? Message { get; set; }
}
