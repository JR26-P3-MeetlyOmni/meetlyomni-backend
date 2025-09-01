// <copyright file="AntiforgeryProtectionMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Options;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipAntiforgeryAttribute : Attribute
{
}

public sealed class AntiforgeryProtectionOptions
{
    public string[] CookieNames { get; set; } = Array.Empty<string>();

    public Func<HttpContext, bool>? ShouldValidate { get; set; }
}

public sealed class AntiforgeryProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<AntiforgeryProtectionOptions> _opt;

    public AntiforgeryProtectionMiddleware(RequestDelegate next, IOptionsMonitor<AntiforgeryProtectionOptions> opt)
    {
        _next = next;
        _opt = opt;
    }

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

            bool usesCookies = opt.CookieNames.Any(n => ctx.Request.Cookies.ContainsKey(n));

            // Force CSRF on auth endpoints even if cookies are not yet present
            bool isAuthEndpoint = ctx.Request.Path.StartsWithSegments("/api/v1/auth", StringComparison.OrdinalIgnoreCase)
                               || ctx.Request.Path.StartsWithSegments("/api/v2/auth", StringComparison.OrdinalIgnoreCase);

            bool needValidate = isUnsafe && !hasBearer && (usesCookies || isAuthEndpoint);
            if (opt.ShouldValidate is not null)
            {
                needValidate = opt.ShouldValidate(ctx);
            }

            if (needValidate)
            {
                await af.ValidateRequestAsync(ctx);
            }
        }

        await _next(ctx);
    }
}
