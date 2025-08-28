// <copyright file="ServiceCollectionExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Asp.Versioning.ApiExplorer;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using Swashbuckle.AspNetCore.SwaggerGen;

namespace MeetlyOmni.Api.Common.Extensions;

/// <summary>
/// Extension methods for configuring services in the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures JWT Bearer authentication with cookie support.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // JWT Authentication Configuration
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            // Disable claim mapping to preserve raw JWT claim types
            options.MapInboundClaims = false;

            // Configure basic validation parameters
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                NameClaimType = "name", // Short claim name
                RoleClaimType = "role", // Short claim name

                // IssuerSigningKey will be set in events below
                // ValidIssuer and ValidAudience will be set in events to use injected options
            };

            // Improved event handling with cookie support
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    // Clone to avoid cross-request races when mutating validation parameters
                    context.Options.TokenValidationParameters =
                        context.Options.TokenValidationParameters.Clone();

                    // Set the signing key at runtime to avoid BuildServiceProvider
                    var keyProvider = context.HttpContext.RequestServices.GetRequiredService<IJwtKeyProvider>();
                    context.Options.TokenValidationParameters.IssuerSigningKey = keyProvider.GetValidationKey();

                    // Set issuer and audience from injected options to ensure consistency
                    var jwtOptions = context.HttpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<JwtOptions>>();
                    context.Options.TokenValidationParameters.ValidIssuer = jwtOptions.Value.Issuer;
                    context.Options.TokenValidationParameters.ValidAudience = jwtOptions.Value.Audience;

                    // Standard JWT Bearer token authentication
                    // Token should be provided in Authorization header as "Bearer <token>"
                    // No cookie fallback needed for access tokens
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    if (context.Exception is SecurityTokenExpiredException ste)
                    {
                        logger.LogWarning("JWT authentication failed: token expired at {Expires}.", ste.Expires);
                    }
                    else if (context.Exception is Microsoft.IdentityModel.Tokens.SecurityTokenInvalidAudienceException)
                    {
                        logger.LogError("JWT authentication failed: Invalid audience");
                    }
                    else
                    {
                        logger.LogWarning("JWT authentication failed: {ErrorType}.", context.Exception.GetType().Name);
                    }

                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    logger.LogDebug(
                        "JWT token validated for user: {UserId}",
                        context.Principal?.FindFirstValue("sub"));
                    return Task.CompletedTask;
                },
            };
        });

        return services;
    }

    /// <summary>
    /// Configures CORS with cookie support for specified origins.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="allowedOrigins">Array of allowed origins. If null, uses default development origins.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddCorsWithCookieSupport(this IServiceCollection services, string[]? allowedOrigins = null)
    {
        var origins = allowedOrigins ?? new[]
        {
            "http://localhost:3000", // React dev server
            "https://localhost:3000", // React dev server with HTTPS
            "http://localhost:5173", // Vite dev server
            "https://localhost:5173", // Vite dev server with HTTPS
        };

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.WithOrigins(origins)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials(); // Essential for cookies
            });
        });

        return services;
    }

    /// <summary>
    /// Configures Swagger/OpenAPI with API versioning support.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="title">API title. Defaults to "MeetlyOmni API".</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSwaggerWithApiVersioning(this IServiceCollection services, string title = "MeetlyOmni API")
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            // Documents configured via IConfigureOptions<SwaggerGenOptions> to avoid building the provider here.
            // Add operation filter to handle API versioning
            options.OperationFilter<SwaggerDefaultValues>();

            // JWT auth configuration for Swagger UI
            var bearerSecurityScheme = new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
            };
            options.AddSecurityDefinition("Bearer", bearerSecurityScheme);

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer",
                        },
                    },
                    Array.Empty<string>()
                },
            });
        });

        services.AddTransient<IConfigureOptions<SwaggerGenOptions>>(
            sp => new ConfigureSwaggerOptions(sp.GetRequiredService<IApiVersionDescriptionProvider>(), title));

        return services;
    }
}
