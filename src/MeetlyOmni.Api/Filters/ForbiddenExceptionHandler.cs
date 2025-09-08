// <copyright file="ForbiddenExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public sealed class ForbiddenExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        if (ex is not ForbiddenAppException)
        {
            return false;
        }

        var pd = new ProblemDetails
        {
            Title = "Forbidden",
            Detail = ex.Message,
            Status = StatusCodes.Status403Forbidden,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };

        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        await ProblemWriter.WriteAsync(ctx, pd, ct);
        return true;
    }
}
