// <copyright file="ApplicationBuilderExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Asp.Versioning.ApiExplorer;

using Microsoft.AspNetCore.Builder;

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
}
