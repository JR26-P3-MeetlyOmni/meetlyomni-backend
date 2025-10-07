// <copyright file="IRefreshTokenRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Repository.Interfaces;

/// <summary>
/// Following .NET best practices: Repository handles tracking, Service handles transactions.
/// </summary>
public interface IRefreshTokenRepository
{
    void Add(RefreshToken refreshToken);

    Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken ct = default);

    Task<RefreshToken?> FindByFamilyIdAsync(Guid familyId, CancellationToken ct = default);

    void Update(RefreshToken refreshToken);

    Task<int> MarkTokenFamilyAsRevokedAsync(Guid familyId, CancellationToken ct = default);

    Task<int> MarkExpiredTokensForRemovalAsync(DateTimeOffset beforeDate, CancellationToken ct = default);

    Task<int> MarkSingleTokenAsReplacedAsync(Guid tokenId, string newTokenHash, CancellationToken ct = default);
}
