// <copyright file="AntiforgeryProtectionMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Options;

namespace MeetlyOmni.Api.Middlewares.Antiforgery;

/// <summary>
/// Middleware that provides CSRF protection for cookie-based authentication.
/// </summary>
public sealed class AntiforgeryProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<AntiforgeryProtectionOptions> _opt;

    /// <summary>
    /// Initializes a new instance of the <see cref="AntiforgeryProtectionMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="opt">The antiforgery protection options.</param>
    public AntiforgeryProtectionMiddleware(RequestDelegate next, IOptionsMonitor<AntiforgeryProtectionOptions> opt)
    {
        _next = next;
        _opt = opt;
    }

    /// <summary>
    /// Invokes the middleware to perform CSRF validation if needed.
    /// </summary>
    /// <param name="ctx">The HTTP context.</param>
    /// <param name="af">The antiforgery service.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext ctx, IAntiforgery af)
    {
        var opt = _opt.CurrentValue;
        var skip = ctx.GetEndpoint()?.Metadata?.GetMetadata<SkipAntiforgeryAttribute>() is not null;

        if (!skip)
        {
            bool isUnsafe = HttpMethods.IsPost(ctx.Request.Method)
                         || HttpMethods.IsPut(ctx.Request.Method)
                         || HttpMethods.IsPatch(ctx.Request.Method)
                         || HttpMethods.IsDelete(ctx.Request.Method);

            bool hasBearer = ctx.Request.Headers.Authorization.ToString()
                .StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);

            bool usesCookies = opt.CookieNames?.Any(n => ctx.Request.Cookies.ContainsKey(n)) ?? false;

            // Force CSRF on auth endpoints even if cookies are not yet present
            bool isAuthEndpoint = ctx.Request.Path.StartsWithSegments("/api/v1/auth", StringComparison.OrdinalIgnoreCase)
                               || ctx.Request.Path.StartsWithSegments("/api/v2/auth", StringComparison.OrdinalIgnoreCase);

            bool needValidate = isUnsafe && !hasBearer && (usesCookies || isAuthEndpoint);
            if (opt.ShouldValidate is not null)
            {
                // Custom predicate can only add validation, not remove it.
                needValidate = needValidate || opt.ShouldValidate(ctx);
            }

            if (needValidate)
            {
                await af.ValidateRequestAsync(ctx);
            }
        }

        await _next(ctx);
    }
}
