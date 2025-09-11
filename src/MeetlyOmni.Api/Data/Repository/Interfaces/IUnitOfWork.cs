// <copyright file="IUnitOfWork.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Repository.Interfaces;

/// <summary>
/// Unit of Work pattern interface for managing database transactions.
/// </summary>
public interface IUnitOfWork : IDisposable
{
    IRefreshTokenRepository RefreshTokens { get; }

    Task<int> SaveChangesAsync(CancellationToken ct = default);

    Task BeginTransactionAsync(CancellationToken ct = default);

    Task CommitTransactionAsync(CancellationToken ct = default);

    Task RollbackTransactionAsync();
}
