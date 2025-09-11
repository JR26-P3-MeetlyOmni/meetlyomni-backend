// <copyright file="InternalLoginResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

/// <summary>
/// Internal login response containing all token information.
/// This is used internally between services and controllers, never returned to clients.
/// </summary>
public class InternalLoginResponse
{
    public string AccessToken { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    public string TokenType { get; set; } = "Bearer";

    public string RefreshToken { get; set; } = string.Empty;

    public DateTimeOffset RefreshTokenExpiresAt { get; set; }
}
