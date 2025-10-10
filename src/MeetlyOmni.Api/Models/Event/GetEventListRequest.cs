// <copyright file="GetEventListRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Event;

/// <summary>
/// Request model for getting event list with pagination.
/// </summary>
public class GetEventListRequest
{
    /// <summary>
    /// Organization ID to filter events.
    /// </summary>
    [Required(ErrorMessage = "Organization ID is required.")]
    public Guid OrgId { get; set; }

    /// <summary>
    /// Page number (1-based). Default is 1.
    /// </summary>
    [Range(1, int.MaxValue, ErrorMessage = "Page number must be greater than 0.")]
    public int PageNumber { get; set; } = 1;

    /// <summary>
    /// Number of items per page. Default is 20, max is 100.
    /// </summary>
    [Range(1, 100, ErrorMessage = "Page size must be between 1 and 100.")]
    public int PageSize { get; set; } = 20;
}

