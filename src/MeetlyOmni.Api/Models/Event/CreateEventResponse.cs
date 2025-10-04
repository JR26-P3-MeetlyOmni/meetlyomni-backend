// <copyright file="CreateEventResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.Event;

namespace MeetlyOmni.Api.Models.Event;

/// <summary>
/// Response model for event creation.
/// </summary>
public class CreateEventResponse
{
    /// <summary>
    /// Unique identifier of the created event.
    /// </summary>
    public Guid EventId { get; set; }

    /// <summary>
    /// Organization ID that owns this event.
    /// </summary>
    public Guid OrgId { get; set; }

    /// <summary>
    /// Event title.
    /// </summary>
    public string Title { get; set; } = default!;

    /// <summary>
    /// Event description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// URL of the event cover image.
    /// </summary>
    public string? CoverImageUrl { get; set; }

    /// <summary>
    /// Event location.
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Event language preference.
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// Current event status.
    /// </summary>
    public EventStatus Status { get; set; }

    /// <summary>
    /// Event start time. Hidden from create response per requirements.
    /// </summary>
    // Removed from create response exposure
    // public DateTimeOffset? StartTime { get; set; }

    /// <summary>
    /// Event end time. Hidden from create response per requirements.
    /// </summary>
    // Removed from create response exposure
    // public DateTimeOffset? EndTime { get; set; }

    /// <summary>
    /// Name of the user who created this event.
    /// </summary>
    public string? CreatedByName { get; set; }

    /// <summary>
    /// Avatar URL of the user who created this event.
    /// </summary>
    public string? CreatedByAvatar { get; set; }

    /// <summary>
    /// Timestamp when the event was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Timestamp when the event was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}

