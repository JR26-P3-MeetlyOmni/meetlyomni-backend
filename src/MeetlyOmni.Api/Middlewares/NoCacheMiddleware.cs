// <copyright file="NoCacheMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.Net.Http.Headers;

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
        // Apply no-cache headers for authentication-related endpoints BEFORE calling next middleware
        if (IsAuthenticationEndpoint(context.Request.Path))
        {
            context.Response.OnStarting(() =>
            {
                var th = context.Response.GetTypedHeaders();
                th.CacheControl = new CacheControlHeaderValue
                {
                    NoCache = true,
                    NoStore = true,
                    MustRevalidate = true,
                    MaxAge = TimeSpan.Zero,
                };
                context.Response.Headers[HeaderNames.Pragma] = "no-cache";
                th.Expires = DateTimeOffset.UnixEpoch;
                return Task.CompletedTask;
            });
        }

        // Call the next middleware in the pipeline
        await _next(context);
    }

    private static bool IsAuthenticationEndpoint(PathString path)
    {
        return path.StartsWithSegments("/api/v1/auth", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWithSegments("/api/v2/auth", StringComparison.OrdinalIgnoreCase);
    }
}
