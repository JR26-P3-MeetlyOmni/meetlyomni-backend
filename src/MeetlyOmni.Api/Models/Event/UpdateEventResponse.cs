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
    /// Gets or sets event unique identifier.
    /// </summary>
    public Guid EventId { get; set; }

    /// <summary>
    /// Gets or sets organization ID that owns this event.
    /// </summary>
    public Guid OrgId { get; set; }

    /// <summary>
    /// Gets or sets event title.
    /// </summary>
    public string Title { get; set; } = default!;

    /// <summary>
    /// Gets or sets event description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets uRL of the event cover image.
    /// </summary>
    public string? CoverImageUrl { get; set; }

    /// <summary>
    /// Gets or sets event location.
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Gets or sets event language preference.
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// Gets or sets event status.
    /// </summary>
    public EventStatus Status { get; set; }

    /// <summary>
    /// Gets or sets event start time.
    /// </summary>
    public DateTimeOffset? StartTime { get; set; }

    /// <summary>
    /// Gets or sets event end time.
    /// </summary>
    public DateTimeOffset? EndTime { get; set; }

    /// <summary>
    /// Gets or sets when the event was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets when the event was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
