// <copyright file="EventController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Asp.Versioning;

using MeetlyOmni.Api.Models.Event;
using MeetlyOmni.Api.Service.EventService.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Event management endpoints.
/// </summary>
[Route("api/v{version:apiVersion}/events")]
[ApiController]
[ApiVersion("1.0")]
public class EventController : ControllerBase
{
    private readonly IEventService _eventService;
    private readonly ILogger<EventController> _logger;

    public EventController(IEventService eventService, ILogger<EventController> logger)
    {
        _eventService = eventService;
        _logger = logger;
    }

    /// <summary>
    /// Create a new event.
    /// </summary>
    /// <param name="request">Create event payload.</param>
    /// <returns>The created event info.</returns>
    [HttpPost]
    [Authorize]
    [ProducesResponseType(typeof(CreateEventResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    public async Task<IActionResult> CreateAsync([FromBody] CreateEventRequest request, CancellationToken ct)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub) || !Guid.TryParse(sub, out var userId))
        {
            return Unauthorized(new ProblemDetails { Title = "Missing subject (sub) claim" });
        }

        // Get user name from JWT claims
        var userName = User.FindFirst("name")?.Value ?? User.FindFirst("email")?.Value ?? "System User";

        var result = await _eventService.CreateEventAsync(request, userId, userName, ct);
        return StatusCode(StatusCodes.Status201Created, result);
    }
}
