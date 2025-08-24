// <copyright file="LoginResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public class LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    public string TokenType { get; set; } = "Bearer";
}
