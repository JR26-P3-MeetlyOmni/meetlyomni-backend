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
    Task<TokenResult> GenerateTokenPairAsync(
        Member user,
        string userAgent,
        string ipAddress,
        Guid? familyId = null);

    Task<string> GenerateAccessTokenAsync(Member user);

    Task<TokenResult> RefreshTokenPairAsync(
        string refreshToken,
        string userAgent,
        string ipAddress);
}
