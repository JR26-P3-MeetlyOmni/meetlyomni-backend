// <copyright file="InviteMemberResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Invitation;

/// <summary>
/// Response model for member invitation.
/// </summary>
public class InviteMemberResponse
{
    /// <summary>
    /// Gets or sets a value indicating whether indicates if the invitation was sent successfully.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Gets or sets message describing the result of the invitation.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets email address of the invited member.
    /// </summary>
    public string Email { get; set; } = string.Empty;
}
