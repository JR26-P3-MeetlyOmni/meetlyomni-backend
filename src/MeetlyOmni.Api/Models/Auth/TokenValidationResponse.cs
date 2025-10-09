// <copyright file="TokenValidationResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public sealed class TokenValidationResponse
{
    public bool IsValid { get; init; }

    public string Message { get; init; } = string.Empty;

    public string Email { get; init; } = string.Empty;
}
