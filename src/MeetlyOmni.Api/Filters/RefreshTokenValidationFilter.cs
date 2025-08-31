// <copyright file="RefreshTokenValidationFilter.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Filters;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MeetlyOmni.Api.Filters;

/// <summary>
/// Action filter to validate refresh token presence in cookies.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class RefreshTokenValidationFilter : ActionFilterAttribute
{
    /// <summary>
    /// Called before the action executes.
    /// </summary>
    /// <param name="context">The action executing context.</param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Check if refresh token exists in cookies
        if (!context.HttpContext.Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
            string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new UnauthorizedAppException("Refresh token is missing.");
        }

        base.OnActionExecuting(context);
    }
}
