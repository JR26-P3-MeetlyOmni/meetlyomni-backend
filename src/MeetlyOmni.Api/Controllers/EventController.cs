// <copyright file="EventController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Asp.Versioning;

using MeetlyOmni.Api.Authorization.Requirements;
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
    private readonly IAuthorizationService _authorizationService;
    private readonly ILogger<EventController> _logger;

    public EventController(
        IEventService eventService,
        IAuthorizationService authorizationService,
        ILogger<EventController> logger)
    {
        _eventService = eventService;
        _authorizationService = authorizationService;
        _logger = logger;
    }

    /// <summary>
    /// Get paginated list of events for an organization.
    /// </summary>
    /// <param name="request">Get event list request with pagination parameters.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Paginated event list.</returns>
    [HttpGet]
    [Authorize]
    [ProducesResponseType(typeof(GetEventListResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetListAsync(
        [FromQuery] GetEventListRequest request,
        CancellationToken ct = default)
    {
        var result = await _eventService.GetEventListAsync(request, ct);
        return Ok(result);
    }

    /// <summary>
    /// Get event by ID.
    /// </summary>
    /// <param name="eventId">Event ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Event details.</returns>
    [HttpGet("{eventId}")]
    [Authorize]
    [ProducesResponseType(typeof(GetEventByIdResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetByIdAsync(Guid eventId, CancellationToken ct = default)
    {
        var result = await _eventService.GetEventByIdAsync(eventId, ct);
        return Ok(result);
    }

    /// <summary>
    /// Create a new event.
    /// </summary>
    /// <param name="request">Create event payload.</param>
    /// <param name="ct">Cancellation token.</param>
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

    /// <summary>
    /// Update an existing event.
    /// </summary>
    /// <param name="eventId">Event ID to update.</param>
    /// <param name="request">Update event payload.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The updated event info.</returns>
    [HttpPut("{eventId}")]
    [Authorize]
    [ProducesResponseType(typeof(UpdateEventResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateAsync(
        Guid eventId,
        [FromBody] UpdateEventRequest request,
        CancellationToken ct = default)
    {
        // Get existing event entity for authorization check
        var existingEvent = await _eventService.GetEventEntityByIdAsync(eventId, ct);

        // Check authorization using policy
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            existingEvent,
            new SameOrganizationRequirement());

        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        // Update event (no userId needed for permission check)
        var result = await _eventService.UpdateEventAsync(eventId, request, ct);
        return Ok(result);
    }

    /// <summary>
    /// Delete an event.
    /// </summary>
    /// <param name="eventId">Event ID to delete.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>No content on successful deletion.</returns>
    [HttpDelete("{eventId}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteAsync(Guid eventId, CancellationToken ct = default)
    {
        // Get existing event entity for authorization check
        var existingEvent = await _eventService.GetEventEntityByIdAsync(eventId, ct);

        // Check authorization using policy
        var authResult = await _authorizationService.AuthorizeAsync(
            User,
            existingEvent,
            new SameOrganizationRequirement());

        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        // Delete event (no userId needed for permission check)
        await _eventService.DeleteEventAsync(eventId, ct);
        return NoContent();
    }
}
