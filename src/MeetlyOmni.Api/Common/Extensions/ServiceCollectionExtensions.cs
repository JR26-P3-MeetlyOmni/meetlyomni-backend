// <copyright file="ServiceCollectionExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

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
            // Get configuration first
            var jwtConfig = configuration.GetSection("Jwt").Get<JwtOptions>();
            if (jwtConfig == null)
            {
                throw new InvalidOperationException("JWT configuration is missing or invalid.");
            }

            // Configure basic validation parameters
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtConfig.Issuer,
                ValidAudience = jwtConfig.Audience,
                ClockSkew = TimeSpan.FromMinutes(1),
                RequireExpirationTime = true,
                RequireSignedTokens = true,

                // IssuerSigningKey will be set in events below
            };

            // Improved event handling with cookie support
            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = context =>
                {
                    // Set the signing key at runtime to avoid BuildServiceProvider
                    var keyProvider = context.HttpContext.RequestServices.GetRequiredService<IJwtKeyProvider>();
                    context.Options.TokenValidationParameters.IssuerSigningKey = keyProvider.GetValidationKey();

                    // Check for JWT token in Authorization header first (standard bearer token)
                    if (string.IsNullOrEmpty(context.Token))
                    {
                        // If no bearer token, try to get token from cookie
                        if (context.Request.Cookies.TryGetValue("access_token", out var cookieToken))
                        {
                            context.Token = cookieToken;
                        }
                    }

                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    if (context.Exception is SecurityTokenExpiredException ste)
                    {
                        logger.LogWarning("JWT authentication failed: token expired at {Expires}.", ste.Expires);
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
                        context.Principal?.FindFirst("sub")?.Value);
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
    public static IServiceCollection AddCorsWithCookieSupport(this IServiceCollection services, string[] ? allowedOrigins = null)
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
    /// Configures Swagger/OpenAPI with JWT Bearer authentication support.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="title">API title. Defaults to "MeetlyOmni API".</param>
    /// <param name="version">API version. Defaults to "v1".</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSwaggerWithJwtAuth(this IServiceCollection services, string title = "MeetlyOmni API", string version = "v1")
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc(version, new OpenApiInfo { Title = title, Version = version });

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
            c.AddSecurityDefinition("Bearer", bearerSecurityScheme);

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
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

        return services;
    }
}
