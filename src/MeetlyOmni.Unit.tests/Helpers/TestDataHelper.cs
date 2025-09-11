// <copyright file="TestDataHelper.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Unit.tests.Helpers;

/// <summary>
/// Helper class for creating test data.
/// </summary>
public static class TestDataHelper
{
    /// <summary>
    /// Creates a valid test member.
    /// </summary>
    /// <returns>A Member entity with test data.</returns>
    public static Member CreateTestMember()
    {
        return new Member
        {
            Id = Guid.NewGuid(),
            UserName = "testuser@example.com",
            Email = "testuser@example.com",
            NormalizedEmail = "TESTUSER@EXAMPLE.COM",
            NormalizedUserName = "TESTUSER@EXAMPLE.COM",
            EmailConfirmed = true,
            PasswordHash = "AQAAAAEAACcQAAAAEMockHashForTesting",
            SecurityStamp = Guid.NewGuid().ToString(),
            OrgId = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-30),
            UpdatedAt = DateTimeOffset.UtcNow.AddDays(-1),
            LastLogin = DateTimeOffset.UtcNow.AddDays(-1),
        };
    }

    /// <summary>
    /// Creates a test member with unconfirmed email.
    /// </summary>
    /// <returns>A Member entity with unconfirmed email.</returns>
    public static Member CreateUnconfirmedMember()
    {
        var member = CreateTestMember();
        member.EmailConfirmed = false;
        return member;
    }

    /// <summary>
    /// Creates a valid login request.
    /// </summary>
    /// <returns>A LoginRequest with valid test data.</returns>
    public static LoginRequest CreateValidLoginRequest()
    {
        return new LoginRequest
        {
            Email = "testuser@example.com",
            Password = "TestPassword123!",
        };
    }

    /// <summary>
    /// Creates an invalid login request with missing email.
    /// </summary>
    /// <returns>A LoginRequest with invalid data.</returns>
    public static LoginRequest CreateInvalidLoginRequest()
    {
        return new LoginRequest
        {
            Email = string.Empty,
            Password = "TestPassword123!",
        };
    }

    /// <summary>
    /// Creates a login request with wrong password.
    /// </summary>
    /// <returns>A LoginRequest with wrong password.</returns>
    public static LoginRequest CreateWrongPasswordRequest()
    {
        return new LoginRequest
        {
            Email = "testuser@example.com",
            Password = "WrongPassword123!",
        };
    }

    /// <summary>
    /// Creates a login request for non-existent user.
    /// </summary>
    /// <returns>A LoginRequest for non-existent user.</returns>
    public static LoginRequest CreateNonExistentUserRequest()
    {
        return new LoginRequest
        {
            Email = "nonexistent@example.com",
            Password = "TestPassword123!",
        };
    }

    /// <summary>
    /// Creates a test refresh token entity.
    /// </summary>
    /// <returns>A RefreshToken entity with test data.</returns>
    public static RefreshToken CreateTestRefreshToken()
    {
        return new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = "test-refresh-token-hash",
            UserId = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1),
            IpAddress = "192.168.1.100",
            UserAgent = "TestUserAgent/1.0",
            RevokedAt = null
        };
    }

    /// <summary>
    /// Creates an expired refresh token entity.
    /// </summary>
    /// <returns>A RefreshToken entity that has expired.</returns>
    public static RefreshToken CreateExpiredRefreshToken()
    {
        var token = CreateTestRefreshToken();
        token.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1); // Expired
        return token;
    }

    /// <summary>
    /// Creates a revoked refresh token entity.
    /// </summary>
    /// <returns>A RefreshToken entity that has been revoked.</returns>
    public static RefreshToken CreateRevokedRefreshToken()
    {
        var token = CreateTestRefreshToken();
        token.RevokedAt = DateTimeOffset.UtcNow.AddMinutes(-5); // Revoked
        return token;
    }
}
