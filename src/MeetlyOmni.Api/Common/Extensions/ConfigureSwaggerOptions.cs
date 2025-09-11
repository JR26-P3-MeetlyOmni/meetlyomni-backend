// <copyright file="ConfigureSwaggerOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Asp.Versioning.ApiExplorer;

using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;

using Swashbuckle.AspNetCore.SwaggerGen;

namespace MeetlyOmni.Api.Common.Extensions;

/// <summary>
/// Configures SwaggerGenOptions to register a Swagger document per API version without building a nested service provider.
/// </summary>
public sealed class ConfigureSwaggerOptions : IConfigureOptions<SwaggerGenOptions>
{
    private readonly IApiVersionDescriptionProvider _provider;
    private readonly string _title;

    public ConfigureSwaggerOptions(IApiVersionDescriptionProvider provider, string title = "MeetlyOmni API")
    {
        _provider = provider;
        _title = title;
    }

    public void Configure(SwaggerGenOptions options)
    {
        foreach (var description in _provider.ApiVersionDescriptions)
        {
            options.SwaggerDoc(description.GroupName, new OpenApiInfo
            {
                Title = $"{_title} {description.ApiVersion}",
                Version = description.ApiVersion.ToString(),
                Description = description.IsDeprecated
                    ? $"{_title} {description.ApiVersion} - This API version has been deprecated."
                    : $"{_title} {description.ApiVersion}",
            });
        }
    }
}
