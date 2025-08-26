// <copyright file="LoginResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public class LoginResponse
{
    public DateTimeOffset ExpiresAt { get; set; }

    public string TokenType { get; set; } = "Bearer";

    // Note: AccessToken and RefreshToken are intentionally omitted
    // They are delivered via HttpOnly cookies for security
}
