// <copyright file="NoCacheMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Middlewares;

/// <summary>
/// Middleware to prevent caching of authentication-related responses.
/// This is important even when using cookie-based JWT storage to ensure
/// consistent behavior and prevent any potential caching issues.
/// </summary>
public class NoCacheMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<NoCacheMiddleware> _logger;

    public NoCacheMiddleware(RequestDelegate next, ILogger<NoCacheMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Call the next middleware in the pipeline
            await _next(context);

            // Apply no-cache headers only for authentication-related endpoints
            if (IsAuthenticationEndpoint(context.Request.Path) &&
                context.Response.StatusCode == 200 &&
                context.Response.ContentType?.Contains("application/json") == true)
            {
                context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
                context.Response.Headers.Pragma = "no-cache";
                context.Response.Headers.Expires = "0";

                _logger.LogDebug("Applied no-cache headers for authentication endpoint: {Path}", context.Request.Path);
            }
        }
        catch
        {
            // Re-throw to let the global exception handler deal with it
            throw;
        }
    }

    private static bool IsAuthenticationEndpoint(PathString path)
    {
        return path.StartsWithSegments("/api/v1/auth", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWithSegments("/api/v2/auth", StringComparison.OrdinalIgnoreCase);
    }
}
