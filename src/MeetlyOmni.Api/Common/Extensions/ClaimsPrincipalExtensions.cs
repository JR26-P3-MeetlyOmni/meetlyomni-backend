// <copyright file="ClaimsPrincipalExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Api.Common.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static CurrentUserResponse? ToCurrentUserResponse(this ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        string userId =
            user.FindFirstValue("sub") ??
            user.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;

        string email =
            user.FindFirstValue("email") ??
            user.FindFirstValue(ClaimTypes.Email) ?? string.Empty;

        string userName = user.FindFirstValue("name") ?? user.FindFirstValue(ClaimTypes.Name) ?? string.Empty;

        string role = user.FindFirstValue("role") ?? user.FindFirstValue(ClaimTypes.Role) ?? string.Empty;

        string orgId = user.FindFirstValue("org_id") ?? string.Empty;

        return new CurrentUserResponse
        {
            Id = Guid.TryParse(userId, out var guid) ? guid : Guid.Empty,
            Email = email,
            UserName = userName,
            Role = role,
            OrgId = orgId,
        };
    }
}
