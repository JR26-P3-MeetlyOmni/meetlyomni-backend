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
    public async Task<GetEventListResponse> GetEventListAsync(
        Guid orgId,
        int pageNumber,
        int pageSize,
        CancellationToken cancellationToken = default)
    {
        // Validate organization exists
        var organizationExists = await _eventRepository.OrganizationExistsAsync(orgId, cancellationToken);
        if (!organizationExists)
        {
            throw new EntityNotFoundException("Organization", orgId.ToString(), $"Organization with ID {orgId} not found.");
        }

        // Validate pagination parameters
        if (pageNumber < 1)
        {
            throw new DomainValidationException(
                new Dictionary<string, string[]> { { "PageNumber", new[] { "Page number must be greater than 0." } } });
        }

        if (pageSize < 1 || pageSize > 100)
        {
            throw new DomainValidationException(
                new Dictionary<string, string[]> { { "PageSize", new[] { "Page size must be between 1 and 100." } } });
        }

        // Get paginated events
        var (events, totalCount) = await _eventRepository.GetEventsByOrganizationWithPaginationAsync(
            orgId,
            pageNumber,
            pageSize,
            cancellationToken);

        // Calculate total pages
        var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

        // Map to response DTOs
        var eventDtos = events.Select(e => new EventListItemDto
        {
            EventId = e.EventId,
            OrgId = e.OrgId,
            Title = e.Title!,
            Description = e.Description,
            CoverImageUrl = e.CoverImageUrl,
            Location = e.Location,
            Language = e.Language,
            Status = e.Status,
            StartTime = e.StartTime,
            EndTime = e.EndTime,
            CreatedAt = e.CreatedAt,
            UpdatedAt = e.UpdatedAt,
        }).ToList();

        _logger.LogInformation(
            "Retrieved {Count} events for organization {OrgId} (Page {PageNumber}/{TotalPages})",
            eventDtos.Count,
            orgId,
            pageNumber,
            totalPages);

        return new GetEventListResponse
        {
            Events = eventDtos,
            TotalCount = totalCount,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalPages = totalPages,
        };
    }

    /// <inheritdoc />
    public async Task<GetEventByIdResponse> GetEventByIdAsync(
        Guid eventId,
        CancellationToken cancellationToken = default)
    {
        var eventEntity = await _eventRepository.GetByIdAsync(eventId, cancellationToken);

        if (eventEntity == null)
        {
            throw new EntityNotFoundException("Event", eventId.ToString(), $"Event with ID {eventId} not found.");
        }

        _logger.LogInformation("Retrieved event {EventId}", eventId);

        return new GetEventByIdResponse
        {
            EventId = eventEntity.EventId,
            OrgId = eventEntity.OrgId,
            OrganizationName = eventEntity.Organization?.OrganizationName,
            Title = eventEntity.Title!,
            Description = eventEntity.Description,
            CoverImageUrl = eventEntity.CoverImageUrl,
            Location = eventEntity.Location,
            Language = eventEntity.Language,
            Status = eventEntity.Status,
            StartTime = eventEntity.StartTime,
            EndTime = eventEntity.EndTime,
            CreatedAt = eventEntity.CreatedAt,
            UpdatedAt = eventEntity.UpdatedAt,
        };
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
