// <copyright file="RefreshTokenRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;

using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Data.Repository;

/// <summary>
/// Following .NET best practices: Repository handles entity tracking, Service controls transactions.
/// </summary>
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _context;

    public RefreshTokenRepository(ApplicationDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void Add(RefreshToken refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        _context.RefreshTokens.Add(refreshToken);
    }

    public async Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);

        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, ct);
    }

    public async Task<RefreshToken?> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .Where(rt => rt.FamilyId == familyId && rt.RevokedAt == null)
            .OrderByDescending(rt => rt.CreatedAt)
            .FirstOrDefaultAsync(ct);
    }

    public void Update(RefreshToken refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        _context.RefreshTokens.Update(refreshToken);
    }

    public async Task<int> MarkTokenFamilyAsRevokedAsync(Guid familyId, CancellationToken ct = default)
    {
        // Use ExecuteUpdateAsync for better performance and atomicity
        // EF Core 8+ provides collection-level updates without loading entities into memory
        return await _context.RefreshTokens
            .Where(rt => rt.FamilyId == familyId && rt.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                .SetProperty(rt => rt.RevokedAt, _ => DateTimeOffset.UtcNow), ct);
    }

    public async Task<int> MarkExpiredTokensForRemovalAsync(DateTimeOffset beforeDate, CancellationToken ct = default)
    {
        // Use ExecuteDeleteAsync for better performance and atomicity
        // EF Core 8+ provides collection-level deletes without loading entities into memory
        return await _context.RefreshTokens
            .Where(rt => rt.ExpiresAt < beforeDate)
            .ExecuteDeleteAsync(ct);
    }

    public async Task<int> MarkSingleTokenAsReplacedAsync(Guid tokenId, string newTokenHash, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(newTokenHash);

        // Use ExecuteUpdateAsync for atomic conditional update
        // Only update if token is still active (RevokedAt == null) and not already replaced
        return await _context.RefreshTokens
            .Where(rt => rt.Id == tokenId && rt.RevokedAt == null && rt.ReplacedByHash == null)
            .ExecuteUpdateAsync(
                setters => setters
                .SetProperty(rt => rt.RevokedAt, _ => DateTimeOffset.UtcNow)
                .SetProperty(rt => rt.ReplacedByHash, _ => newTokenHash), ct);
    }
}
