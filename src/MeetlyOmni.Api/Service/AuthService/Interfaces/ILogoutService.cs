// <copyright file="ILogoutService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

/// <summary>
/// Service responsible for user logout operations.
/// </summary>
public interface ILogoutService
{
    Task LogoutAsync(HttpContext httpContext, CancellationToken ct = default);
}
