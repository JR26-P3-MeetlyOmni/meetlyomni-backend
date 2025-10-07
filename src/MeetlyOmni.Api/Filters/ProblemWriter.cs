// <copyright file="ProblemWriter.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Filters;

public static class ProblemWriter
{
    public static async Task WriteAsync(HttpContext httpContext, ProblemDetails pd, CancellationToken ct)
    {
        var svc = httpContext.RequestServices.GetRequiredService<IProblemDetailsService>();
        await svc.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = pd,
            Exception = httpContext.Features.Get<IExceptionHandlerFeature>()?.Error,
        });
    }
}
