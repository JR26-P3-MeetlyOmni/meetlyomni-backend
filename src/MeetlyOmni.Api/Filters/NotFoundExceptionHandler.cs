// <copyright file="NotFoundExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public sealed class NotFoundExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        if (ex is not EntityNotFoundException nf)
        {
            return false;
        }

        var pd = new ProblemDetails
        {
            Title = "Resource not found",
            Detail = nf.Message,
            Status = StatusCodes.Status404NotFound,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };
        pd.Extensions["resource"] = nf.Resource;
        pd.Extensions["key"] = nf.Key;

        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        await ProblemWriter.WriteAsync(ctx, pd, ct);
        return true;
    }
}
