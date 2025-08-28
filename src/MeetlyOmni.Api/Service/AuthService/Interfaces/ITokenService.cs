// <copyright file="ITokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

/// <summary>
/// Service responsible for token generation and management.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generate a new access + refresh token pair for a user.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    Task<TokenResult> GenerateTokenPairAsync(
        Member user,
        string userAgent,
        string ipAddress,
        Guid? familyId = null,
        CancellationToken ct = default);

    /// <summary>
    /// Generate a new access token for a user.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    Task<string> GenerateAccessTokenAsync(Member user, CancellationToken ct = default);

    /// <summary>
    /// Refresh token pair using a valid refresh token.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    Task<TokenResult> RefreshTokenPairAsync(
        string refreshToken,
        string userAgent,
        string ipAddress,
        CancellationToken ct = default);

    /// <summary>
    /// Logout from the single device.
    /// </summary>
    /// <returns><placeholder>A <see cref="Task"/> representing the asynchronous operation.</placeholder></returns>
    Task<bool> LogoutAsync(
        string refreshToken,
        CancellationToken ct = default);
}
