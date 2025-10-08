// <copyright file="AcceptInvitationResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Api.Models.Invitation;

/// <summary>
/// Response model for accepting an invitation.
/// </summary>
public class AcceptInvitationResponse
{
    /// <summary>
    /// Gets or sets a value indicating whether indicates if the invitation was accepted successfully.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Gets or sets message describing the result.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets login response containing tokens if successful.
    /// </summary>
    public LoginResponse? LoginResponse { get; set; }
}
