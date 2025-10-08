// <copyright file="IInvitationService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Invitation;

namespace MeetlyOmni.Api.Service.Invitation.Interfaces;

/// <summary>
/// Service for managing member invitations to organizations.
/// </summary>
public interface IInvitationService
{
    /// <summary>
    /// Invite a member to join the organization.
    /// </summary>
    /// <param name="email">Email address of the member to invite.</param>
    /// <param name="message">Optional message to include in the invitation.</param>
    /// <param name="orgId">Organization ID to invite the member to.</param>
    /// <param name="invitedByUserId">ID of the user who is sending the invitation.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Response indicating success or failure.</returns>
    Task<InviteMemberResponse> InviteMemberAsync(
        string email,
        string? message,
        Guid orgId,
        Guid invitedByUserId,
        CancellationToken ct = default);

    /// <summary>
    /// Accept an invitation to join an organization.
    /// </summary>
    /// <param name="request">Accept invitation request containing email, password, and token.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Response containing login information if successful.</returns>
    Task<AcceptInvitationResponse> AcceptInvitationAsync(
        AcceptInvitationRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// Validate an invitation token.
    /// </summary>
    /// <param name="email">Email address.</param>
    /// <param name="token">Invitation token.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if the token is valid, false otherwise.</returns>
    Task<bool> ValidateInvitationTokenAsync(string email, string token, CancellationToken ct = default);
}
