// <copyright file="GetEventListResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.Event;

namespace MeetlyOmni.Api.Models.Event;

/// <summary>
/// Response model for event list item.
/// </summary>
public class EventListItemDto
{
    /// <summary>
    /// Gets or sets the event ID.
    /// </summary>
    public Guid EventId { get; set; }

    /// <summary>
    /// Gets or sets the organization ID.
    /// </summary>
    public Guid OrgId { get; set; }

    /// <summary>
    /// Gets or sets the event title.
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the event description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets the cover image URL.
    /// </summary>
    public string? CoverImageUrl { get; set; }

    /// <summary>
    /// Gets or sets the event location.
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Gets or sets the event language.
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// Gets or sets the event status.
    /// </summary>
    public EventStatus Status { get; set; }

    /// <summary>
    /// Gets or sets the start time.
    /// </summary>
    public DateTimeOffset? StartTime { get; set; }

    /// <summary>
    /// Gets or sets the end time.
    /// </summary>
    public DateTimeOffset? EndTime { get; set; }

    /// <summary>
    /// Gets or sets the created time.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the updated time.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Response model for get event list.
/// </summary>
public class GetEventListResponse
{
    /// <summary>
    /// Gets or sets the list of events.
    /// </summary>
    public List<EventListItemDto> Events { get; set; } = new();

    /// <summary>
    /// Gets or sets the total count of events.
    /// </summary>
    public int TotalCount { get; set; }

    /// <summary>
    /// Gets or sets the current page number.
    /// </summary>
    public int PageNumber { get; set; }

    /// <summary>
    /// Gets or sets the page size.
    /// </summary>
    public int PageSize { get; set; }

    /// <summary>
    /// Gets or sets the total pages.
    /// </summary>
    public int TotalPages { get; set; }
}
