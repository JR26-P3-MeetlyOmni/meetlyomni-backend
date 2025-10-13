// <copyright file="EventService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

using AutoMapper;

using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Event;
using MeetlyOmni.Api.Service.EventService.Interfaces;

using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Service.EventService;

/// <summary>
/// Service implementation for Event business logic operations.
/// </summary>
public class EventService : IEventService
{
    private readonly IEventRepository _eventRepository;
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;
    private readonly ILogger<EventService> _logger;

    public EventService(
        IEventRepository eventRepository,
        ApplicationDbContext context,
        IMapper mapper,
        ILogger<EventService> logger)
    {
        _eventRepository = eventRepository;
        _context = context;
        _mapper = mapper;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<GetEventListResponse> GetEventListAsync(
        GetEventListRequest request,
        CancellationToken cancellationToken = default)
    {
        // Validate organization exists
        var organizationExists = await _eventRepository.OrganizationExistsAsync(request.OrgId, cancellationToken);
        if (!organizationExists)
        {
            throw new EntityNotFoundException("Organization", request.OrgId.ToString(), $"Organization with ID {request.OrgId} not found.");
        }

        // Note: Pagination parameters are validated by DataAnnotations in the DTO

        // Get paginated events
        var (events, totalCount) = await _eventRepository.GetEventsByOrganizationWithPaginationAsync(
            request.OrgId,
            request.PageNumber,
            request.PageSize,
            cancellationToken);

        // Calculate total pages
        var totalPages = (int)Math.Ceiling(totalCount / (double)request.PageSize);

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
            request.OrgId,
            request.PageNumber,
            totalPages);

        return new GetEventListResponse
        {
            Events = eventDtos,
            TotalCount = totalCount,
            PageNumber = request.PageNumber,
            PageSize = request.PageSize,
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

    public async Task<Event> GetEventEntityByIdAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var eventEntity = await _eventRepository.GetByIdAsync(eventId, cancellationToken);

        if (eventEntity == null)
        {
            throw new EntityNotFoundException("Event", eventId.ToString(), $"Event with ID {eventId} not found.");
        }

        return eventEntity;
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
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    public async Task<UpdateEventResponse> UpdateEventAsync(
        Guid eventId,
        UpdateEventRequest request,
        CancellationToken cancellationToken = default)
    {
        // Get existing event
        var existingEvent = await _eventRepository.GetByIdAsync(eventId, cancellationToken);

        if (existingEvent == null)
        {
            throw new EntityNotFoundException("Event", eventId.ToString(), $"Event with ID {eventId} not found.");
        }

        // Note: Authorization is handled by IAuthorizationService in Controller

        // Validate business rules
        ValidateUpdateEventBusinessRules(request);

        // Apply partial updates using AutoMapper (only non-null fields)
        _mapper.Map(request, existingEvent);

        // Update timestamp
        existingEvent.UpdatedAt = DateTimeOffset.UtcNow;

        // Save changes
        var updatedEvent = await _eventRepository.UpdateAsync(existingEvent, cancellationToken);

        _logger.LogInformation(
            "Event {EventId} updated",
            eventId);

        // Map to response DTO
        return new UpdateEventResponse
        {
            EventId = updatedEvent.EventId,
            OrgId = updatedEvent.OrgId,
            Title = updatedEvent.Title!,
            Description = updatedEvent.Description,
            CoverImageUrl = updatedEvent.CoverImageUrl,
            Location = updatedEvent.Location,
            Language = updatedEvent.Language,
            Status = updatedEvent.Status,
            StartTime = updatedEvent.StartTime,
            EndTime = updatedEvent.EndTime,
            CreatedAt = updatedEvent.CreatedAt,
            UpdatedAt = updatedEvent.UpdatedAt,
        };
    }

    public async Task DeleteEventAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        // Get existing event
        var existingEvent = await _eventRepository.GetByIdAsync(eventId, cancellationToken);

        if (existingEvent == null)
        {
            throw new EntityNotFoundException("Event", eventId.ToString(), $"Event with ID {eventId} not found.");
        }

        // Note: Authorization is handled by IAuthorizationService in Controller

        // Delete the event
        await _eventRepository.DeleteAsync(existingEvent, cancellationToken);

        _logger.LogInformation(
            "Event {EventId} deleted",
            eventId);
    }

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

    private static void ValidateUpdateEventBusinessRules(UpdateEventRequest request)
    {
        // Validate time range if both are provided
        if (request.StartTime.HasValue && request.EndTime.HasValue)
        {
            if (request.EndTime.Value <= request.StartTime.Value)
            {
                throw new DomainValidationException(
                    new Dictionary<string, string[]> { { "EndTime", new[] { "End time must be after start time." } } });
            }
        }

        // Validate language code format (basic validation)
        if (!string.IsNullOrEmpty(request.Language) && request.Language.Length > 10)
        {
            throw new DomainValidationException(
                new Dictionary<string, string[]> { { "Language", new[] { "Language code cannot exceed 10 characters." } } });
        }
    }
}
