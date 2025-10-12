// <copyright file="IEventService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
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

    /// <summary>
    /// Get paginated list of events for an organization.
    /// </summary>
    /// <param name="request">Get event list request with pagination parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Paginated event list response.</returns>
    Task<GetEventListResponse> GetEventListAsync(GetEventListRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get event by ID.
    /// </summary>
    /// <param name="eventId">Event ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Event details.</returns>
    Task<GetEventByIdResponse> GetEventByIdAsync(Guid eventId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get event entity by ID (for authorization checks).
    /// </summary>
    /// <param name="eventId">Event ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Event entity.</returns>
    Task<Event> GetEventEntityByIdAsync(Guid eventId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Update an existing event.
    /// </summary>
    /// <param name="eventId">Event ID to update.</param>
    /// <param name="request">Update request payload.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Update response DTO.</returns>
    /// <remarks>Authorization should be checked before calling this method.</remarks>
    Task<UpdateEventResponse> UpdateEventAsync(Guid eventId, UpdateEventRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Delete an event.
    /// </summary>
    /// <param name="eventId">Event ID to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Task representing the asynchronous operation.</returns>
    /// <remarks>Authorization should be checked before calling this method.</remarks>
    Task DeleteEventAsync(Guid eventId, CancellationToken cancellationToken = default);
}
