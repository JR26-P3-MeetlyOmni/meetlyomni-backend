// <copyright file="EventRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;

using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Data.Repository;

/// <summary>
/// Repository implementation for Event entity operations.
/// </summary>
public class EventRepository : IEventRepository
{
    private readonly ApplicationDbContext _context;

    public EventRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task<Event> CreateAsync(Event eventEntity, CancellationToken cancellationToken = default)
    {
        _context.Events.Add(eventEntity);
        await _context.SaveChangesAsync(cancellationToken);
        return eventEntity;
    }

    /// <inheritdoc />
    public async Task<Event?> GetByIdAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        return await _context.Events
            .Include(e => e.Organization)
            .FirstOrDefaultAsync(e => e.EventId == eventId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<Event>> GetByOrganizationIdAsync(Guid orgId, CancellationToken cancellationToken = default)
    {
        return await _context.Events
            .Where(e => e.OrgId == orgId)
            .OrderByDescending(e => e.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> OrganizationExistsAsync(Guid orgId, CancellationToken cancellationToken = default)
    {
        return await _context.Organizations
            .AnyAsync(o => o.OrgId == orgId, cancellationToken);
    }
}
