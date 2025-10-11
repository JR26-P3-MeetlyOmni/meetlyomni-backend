// <copyright file="IEventService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Event;

namespace MeetlyOmni.Api.Service.EventService.Interfaces;

/// <summary>
/// Service contract for Event business operations.
/// </summary>
public interface IEventService
{
    /// <summary>
    /// Create an event.
    /// </summary>
    /// <param name="request">Create request payload.</param>
    /// <param name="creatorId">Authenticated user id.</param>
    /// <param name="creatorName">Authenticated user name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Create response DTO.</returns>
    Task<CreateEventResponse> CreateEventAsync(CreateEventRequest request, Guid creatorId, string creatorName, CancellationToken cancellationToken = default);
}
