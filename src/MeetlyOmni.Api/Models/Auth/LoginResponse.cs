// <copyright file="LoginResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public class LoginResponse
{
    public string? AccessToken { get; set; } // Access token for frontend to store in memory

    public DateTimeOffset ExpiresAt { get; set; }

    public string TokenType { get; set; } = "Bearer";

    // Note: RefreshToken is intentionally omitted
    // It is delivered via HttpOnly cookie for security
}
