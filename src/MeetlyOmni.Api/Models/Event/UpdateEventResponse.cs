// <copyright file="UpdateEventResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.Event;

namespace MeetlyOmni.Api.Models.Event;

/// <summary>
/// Response model for updating an event.
/// </summary>
public class UpdateEventResponse
{
    /// <summary>
    /// Event unique identifier.
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
    /// Event status.
    /// </summary>
    public EventStatus Status { get; set; }

    /// <summary>
    /// Event start time.
    /// </summary>
    public DateTimeOffset? StartTime { get; set; }

    /// <summary>
    /// Event end time.
    /// </summary>
    public DateTimeOffset? EndTime { get; set; }

    /// <summary>
    /// When the event was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When the event was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}

