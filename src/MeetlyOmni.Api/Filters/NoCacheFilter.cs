// <copyright file="NoCacheFilter.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MeetlyOmni.Api.Filters;

/// <summary>
/// Action filter to prevent caching of authentication-related responses.
/// This is important even when using cookie-based JWT storage to ensure
/// consistent behavior and prevent any potential caching issues.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class NoCacheFilter : ActionFilterAttribute
{
    /// <summary>
    /// Called after the action result is executed.
    /// </summary>
    /// <param name="context">The action executed context.</param>
    public override void OnResultExecuted(ResultExecutedContext context)
    {
        // Only apply to successful responses that return data
        if (context.Result is ObjectResult or OkObjectResult)
        {
            // Set cache control headers to prevent caching
            context.HttpContext.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
            context.HttpContext.Response.Headers.Pragma = "no-cache";

            // Additional header for older browsers
            context.HttpContext.Response.Headers.Expires = "0";
        }

        base.OnResultExecuted(context);
    }
}
