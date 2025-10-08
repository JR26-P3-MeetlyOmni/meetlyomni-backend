// <copyright file="CreateEventRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

using MeetlyOmni.Api.Common.Enums.Event;

namespace MeetlyOmni.Api.Models.Event;

/// <summary>
/// Request model for creating a new event.
/// </summary>
public class CreateEventRequest
{
    /// <summary>
    /// Gets or sets organization ID that owns this event.
    /// </summary>
    [Required(ErrorMessage = "Organization ID is required.")]
    public Guid OrgId { get; set; }

    /// <summary>
    /// Gets or sets event title. Required, 1-255 characters.
    /// </summary>
    [Required(ErrorMessage = "Event title is required.")]
    [StringLength(255, MinimumLength = 1, ErrorMessage = "Event title must be between 1 and 255 characters.")]
    public string Title { get; set; } = default!;

    /// <summary>
    /// Gets or sets event description. Optional, max 500 characters.
    /// </summary>
    [StringLength(500, ErrorMessage = "Event description cannot exceed 500 characters.")]
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets uRL of the event cover image. Optional.
    /// </summary>
    [Url(ErrorMessage = "Cover image URL must be a valid URL.")]
    public string? CoverImageUrl { get; set; }

    /// <summary>
    /// Gets or sets event location. Optional, max 255 characters.
    /// </summary>
    [StringLength(255, ErrorMessage = "Event location cannot exceed 255 characters.")]
    public string? Location { get; set; }

    /// <summary>
    /// Gets or sets event language preference. Optional, max 10 characters, defaults to "en".
    /// </summary>
    [StringLength(10, ErrorMessage = "Language code cannot exceed 10 characters.")]
    public string? Language { get; set; } = "en";

    /// <summary>
    /// Gets or sets event status. Defaults to Draft.
    /// </summary>
    public EventStatus Status { get; set; } = EventStatus.Draft;
}
