// <copyright file="UnauthorizedExceptionHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public sealed class UnauthorizedExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext ctx, Exception ex, CancellationToken ct)
    {
        if (ex is not UnauthorizedAppException)
        {
            return false;
        }

        // Clear the refresh token cookie to avoid refresh loops (use same Path/flags as set)
        ctx.Response.DeleteRefreshTokenCookie();
        ctx.Response.DeleteAccessTokenCookie();

        var pd = new ProblemDetails
        {
            Title = "Unauthorized",
            Detail = ex.Message,
            Status = StatusCodes.Status401Unauthorized,
            Type = "about:blank",
            Instance = ctx.Request.Path,
        };

        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ProblemWriter.WriteAsync(ctx, pd, ct);
        return true;
    }
}
