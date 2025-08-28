// <copyright file="AntiforgeryExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public sealed class AntiforgeryExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        if (ex is not AntiforgeryValidationException)
        {
            return false;
        }

        var pd = new ProblemDetails
        {
            Title = "Antiforgery Validation Failed",
            Detail = "CSRF token validation failed. Please refresh the page and try again.",
            Status = StatusCodes.Status400BadRequest,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };

        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        await ProblemWriter.WriteAsync(ctx, pd, ct);
        return true;
    }
}
