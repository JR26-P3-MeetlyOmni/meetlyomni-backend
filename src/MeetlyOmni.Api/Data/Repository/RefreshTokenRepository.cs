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

    public async Task<RefreshToken?> FindByHashAsync(string tokenHash)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);

        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
    }

    public void Update(RefreshToken refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        _context.RefreshTokens.Update(refreshToken);
    }

    public async Task<int> MarkTokenFamilyAsRevokedAsync(Guid familyId)
    {
        var familyTokens = await _context.RefreshTokens
            .Where(rt => rt.FamilyId == familyId && rt.RevokedAt == null)
            .ToListAsync();

        var revokedCount = familyTokens.Count;
        foreach (var token in familyTokens)
        {
            token.RevokedAt = DateTimeOffset.UtcNow;
        }

        return revokedCount;
    }

    public async Task<int> MarkExpiredTokensForRemovalAsync(DateTimeOffset beforeDate)
    {
        var expiredTokens = await _context.RefreshTokens
            .Where(rt => rt.ExpiresAt < beforeDate)
            .ToListAsync();

        if (expiredTokens.Count > 0)
        {
            _context.RefreshTokens.RemoveRange(expiredTokens);
        }

        return expiredTokens.Count;
    }
}
