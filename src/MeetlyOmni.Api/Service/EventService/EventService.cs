// <copyright file="EventService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Event;
using MeetlyOmni.Api.Service.EventService.Interfaces;

namespace MeetlyOmni.Api.Service.EventService;

/// <summary>
/// Service implementation for Event business logic operations.
/// </summary>
public class EventService : IEventService
{
    private readonly IEventRepository _eventRepository;
    private readonly ILogger<EventService> _logger;

    public EventService(IEventRepository eventRepository, ILogger<EventService> logger)
    {
        _eventRepository = eventRepository;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<CreateEventResponse> CreateEventAsync(
        CreateEventRequest request,
        Guid creatorId,
        string creatorName,
        CancellationToken cancellationToken = default)
    {
        // Validate organization exists
        var organizationExists = await _eventRepository.OrganizationExistsAsync(request.OrgId, cancellationToken);
        if (!organizationExists)
        {
            throw new EntityNotFoundException("Organization", request.OrgId.ToString(), $"Organization with ID {request.OrgId} not found.");
        }

        // Validate business rules
        ValidateEventBusinessRules(request);

        // Use the creator name passed from controller

        // Create event entity
        var eventEntity = new Event
        {
            EventId = Guid.NewGuid(),
            OrgId = request.OrgId,
            Title = request.Title.Trim(),
            Description = request.Description?.Trim(),
            CoverImageUrl = request.CoverImageUrl?.Trim(),
            Location = request.Location?.Trim(),
            Language = request.Language?.Trim() ?? "en",
            Status = request.Status,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };

        // Save to database
        var createdEvent = await _eventRepository.CreateAsync(eventEntity, cancellationToken);

        _logger.LogInformation(
            "Event {EventId} created successfully by user {CreatorId}",
            createdEvent.EventId, creatorId);

        // Map to response
        return new CreateEventResponse
        {
            EventId = createdEvent.EventId,
            OrgId = createdEvent.OrgId,
            Title = createdEvent.Title!,
            Description = createdEvent.Description,
            CoverImageUrl = createdEvent.CoverImageUrl,
            Location = createdEvent.Location,
            Language = createdEvent.Language,
            Status = createdEvent.Status,
            CreatedByName = creatorName,
            CreatedByAvatar = null, // TODO: Add avatar URL when available
            CreatedAt = createdEvent.CreatedAt,
            UpdatedAt = createdEvent.UpdatedAt,
        };
    }

    /// <summary>
    /// Validates business rules for event creation.
    /// </summary>
    /// <param name="request">The create event request.</param>
    /// <exception cref="ValidationAppException">Thrown when business rules are violated.</exception>
    private static void ValidateEventBusinessRules(CreateEventRequest request)
    {
        // Time fields are intentionally hidden from create API; no time validation here

        // Validate language code format (basic validation)
        if (!string.IsNullOrEmpty(request.Language) && request.Language.Length > 10)
        {
            throw new DomainValidationException(
                new Dictionary<string, string[]> { { "Language", new[] { "Language code cannot exceed 10 characters." } } });
        }
    }
}
