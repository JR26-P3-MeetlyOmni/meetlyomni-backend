// <copyright file="ApplicationBuilderExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;

using Asp.Versioning.ApiExplorer;

using MeetlyOmni.Api.Middlewares;
using MeetlyOmni.Api.Middlewares.Antiforgery;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace MeetlyOmni.Api.Common.Extensions;

/// <summary>
/// Extension methods for configuring the application builder.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Configures Swagger UI with API versioning support.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseSwaggerWithApiVersioning(this IApplicationBuilder app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            var provider = app.ApplicationServices.GetRequiredService<IApiVersionDescriptionProvider>();

            // Build a swagger endpoint for each discovered API version
            foreach (var description in provider.ApiVersionDescriptions)
            {
                var name = description.GroupName;
                var url = $"/swagger/{name}/swagger.json";
                options.SwaggerEndpoint(url, name.ToUpperInvariant());
            }
        });

        return app;
    }

    /// <summary>
    /// Adds the global exception handler middleware to the application pipeline.
    /// This middleware should be placed early in the pipeline to catch exceptions
    /// from all subsequent middleware and handlers.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder app)
    {
        return app.UseMiddleware<GlobalExceptionHandlerMiddleware>();
    }

    /// <summary>
    /// Adds the no-cache middleware to the application pipeline.
    /// This middleware prevents caching of authentication-related responses.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseNoCache(this IApplicationBuilder app)
    {
        return app.UseMiddleware<NoCacheMiddleware>();
    }

    /// <summary>
    /// Adds antiforgery protection middleware using DI-registered options.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseAntiforgeryProtection(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AntiforgeryProtectionMiddleware>();
    }
}
