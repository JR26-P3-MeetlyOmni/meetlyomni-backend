// <copyright file="ILoginService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

/// <summary>
/// Service responsible for user authentication and login.
/// </summary>
public interface ILoginService
{
    /// <summary>
    /// Authenticates user credentials and returns internal login response with tokens.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    Task<InternalLoginResponse> LoginAsync(LoginRequest request, string userAgent, string ipAddress);
}
