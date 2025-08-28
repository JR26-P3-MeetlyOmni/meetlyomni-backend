// <copyright file="GlobalUnhandledExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public sealed class GlobalUnhandledExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalUnhandledExceptionHandler> _logger;

    public GlobalUnhandledExceptionHandler(ILogger<GlobalUnhandledExceptionHandler> logger) => _logger = logger;

    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        _logger.LogError(ex, "Unhandled exception");

        var pd = new ProblemDetails
        {
            Title = "Internal Server Error",
            Detail = "An unexpected error occurred. Please try again later.",
            Status = StatusCodes.Status500InternalServerError,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };

        // add trace id to problem details for easier correlation
        pd.Extensions["traceId"] = ctx.TraceIdentifier;

        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await ProblemWriter.WriteAsync(ctx, pd, ct);
        return true;
    }
}
