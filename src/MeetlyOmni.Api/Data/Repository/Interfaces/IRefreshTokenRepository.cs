// <copyright file="IRefreshTokenRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Repository.Interfaces;

/// <summary>
/// Repository interface for refresh token operations.
/// Following .NET best practices: Repository handles tracking, Service handles transactions.
/// </summary>
public interface IRefreshTokenRepository
{
    /// <summary>
    /// Adds a new refresh token to the context (tracked, not persisted until SaveChanges).
    /// </summary>
    /// <param name="refreshToken">The refresh token to add.</param>
    void Add(RefreshToken refreshToken);

    /// <summary>
    /// Finds a refresh token by its hash value.
    /// </summary>
    /// <param name="tokenHash">The hash of the token to find.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the refresh token if found, otherwise null.</returns>
    Task<RefreshToken?> FindByHashAsync(string tokenHash);

    /// <summary>
    /// Updates an existing refresh token (tracked, not persisted until SaveChanges).
    /// </summary>
    /// <param name="refreshToken">The refresh token to update.</param>
    void Update(RefreshToken refreshToken);

    /// <summary>
    /// Finds and marks tokens in a family as revoked (tracked, not persisted until SaveChanges).
    /// </summary>
    /// <param name="familyId">The family ID of tokens to revoke.</param>
    /// <returns>A task that returns the number of tokens marked for revocation.</returns>
    Task<int> MarkTokenFamilyAsRevokedAsync(Guid familyId);

    /// <summary>
    /// Finds and marks expired tokens for removal (tracked, not persisted until SaveChanges).
    /// </summary>
    /// <param name="beforeDate">Remove tokens that expired before this date.</param>
    /// <returns>A task that returns the number of tokens marked for removal.</returns>
    Task<int> MarkExpiredTokensForRemovalAsync(DateTimeOffset beforeDate);
}
