// <copyright file="TokenResult.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Service.JwtService;

public record TokenResult(string accessToken, DateTimeOffset expiresAt);
