// <copyright file="RefreshToken.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities;

/// <summary>
/// Represents a refresh token for secure token rotation.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public string TokenHash { get; set; } = string.Empty;

    public Guid FamilyId { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset FamilyExpiresAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? ReplacedByHash { get; set; }

    public string UserAgent { get; set; } = string.Empty;

    public string IpAddress { get; set; } = string.Empty;

    public bool IsActive => RevokedAt == null && ExpiresAt > DateTimeOffset.UtcNow && FamilyExpiresAt > DateTimeOffset.UtcNow;

    public bool IsReplaced => !string.IsNullOrEmpty(ReplacedByHash);

    public Member User { get; set; } = null!;
}
