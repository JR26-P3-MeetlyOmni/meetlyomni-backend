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

    Task<RefreshToken?> FindByHashAsync(string tokenHash);

    void Update(RefreshToken refreshToken);

    Task<int> MarkTokenFamilyAsRevokedAsync(Guid familyId);

    Task<int> MarkExpiredTokensForRemovalAsync(DateTimeOffset beforeDate);
}
