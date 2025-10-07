// <copyright file="ValidationExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Diagnostics;

namespace MeetlyOmni.Api.Filters;

public sealed class ValidationExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        if (ex is not DomainValidationException vex)
        {
            return false;
        }

        var vpd = new HttpValidationProblemDetails((IDictionary<string, string[]>)vex.Errors)
        {
            Title = "Validation failed",
            Detail = vex.Message,
            Status = StatusCodes.Status400BadRequest,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };

        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        await ProblemWriter.WriteAsync(ctx, vpd, ct);
        return true;
    }
}
