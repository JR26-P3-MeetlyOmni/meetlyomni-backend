// <copyright file="IEventRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Repository.Interfaces;

/// <summary>
/// Repository interface for Event entity operations.
/// </summary>
public interface IEventRepository
{
    /// <summary>
    /// Creates a new event in the database.
    /// </summary>
    /// <param name="eventEntity">The event entity to create.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created event entity with generated ID.</returns>
    Task<Event> CreateAsync(Event eventEntity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an event by its ID.
    /// </summary>
    /// <param name="eventId">The event ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The event entity, or null if not found.</returns>
    Task<Event?> GetByIdAsync(Guid eventId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets events by organization ID.
    /// </summary>
    /// <param name="orgId">The organization ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of events for the organization.</returns>
    Task<IEnumerable<Event>> GetByOrganizationIdAsync(Guid orgId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if an organization exists.
    /// </summary>
    /// <param name="orgId">The organization ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if organization exists, false otherwise.</returns>
    Task<bool> OrganizationExistsAsync(Guid orgId, CancellationToken cancellationToken = default);
}
