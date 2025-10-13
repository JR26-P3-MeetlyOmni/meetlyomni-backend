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
    /// Gets or sets unique identifier of the created event.
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
    /// Gets or sets current event status.
    /// </summary>
    public EventStatus Status { get; set; }

    /// <summary>
    /// Gets or sets event start time. Hidden from create response per requirements.
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
    /// Gets or sets avatar URL of the user who created this event.
    /// </summary>
    public string? CreatedByAvatar { get; set; }

    /// <summary>
    /// Gets or sets timestamp when the event was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets timestamp when the event was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
