// <copyright file="TokenResult.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public record TokenResult(
    string accessToken,
    DateTimeOffset accessTokenExpiresAt,
    string refreshToken,
    DateTimeOffset refreshTokenExpiresAt);
