// <copyright file="GlobalExceptionHandlerMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Filters;

using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace MeetlyOmni.Api.Middlewares;

/// <summary>
/// Global exception handling middleware that provides centralized error handling
/// for the entire HTTP pipeline, following RFC 7807 Problem Details specification.
/// </summary>
public class GlobalExceptionHandlerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionHandlerMiddleware> _logger;
    private readonly IWebHostEnvironment _environment;

    public GlobalExceptionHandlerMiddleware(
        RequestDelegate next,
        ILogger<GlobalExceptionHandlerMiddleware> logger,
        IWebHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _environment = environment;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private static void ClearAuthenticationCookies(HttpContext context)
    {
        context.Response.DeleteAccessTokenCookie();
        context.Response.DeleteRefreshTokenCookie();
    }

    private static string GetProblemType(int statusCode) => statusCode switch
    {
        StatusCodes.Status400BadRequest => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
        StatusCodes.Status401Unauthorized => "https://tools.ietf.org/html/rfc7235#section-3.1",
        StatusCodes.Status403Forbidden => "https://tools.ietf.org/html/rfc7231#section-6.5.3",
        StatusCodes.Status404NotFound => "https://tools.ietf.org/html/rfc7231#section-6.5.4",
        StatusCodes.Status409Conflict => "https://tools.ietf.org/html/rfc7231#section-6.5.8",
        StatusCodes.Status500InternalServerError => "https://tools.ietf.org/html/rfc7231#section-6.6.1",
        _ => "https://tools.ietf.org/html/rfc7231#section-6.6.1"
    };

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        _logger.LogError(exception, "Unhandled exception: {Url}", context.Request.GetDisplayUrl());

        var (statusCode, title) = exception switch
        {
            UnauthorizedAppException => (StatusCodes.Status401Unauthorized, "Unauthorized"),
            DomainValidationException => (StatusCodes.Status400BadRequest, "Validation failed"),
            EntityNotFoundException => (StatusCodes.Status404NotFound, "Not found"),
            ConflictAppException => (StatusCodes.Status409Conflict, "Conflict"),
            ForbiddenAppException => (StatusCodes.Status403Forbidden, "Forbidden"),
            Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException => (StatusCodes.Status403Forbidden, "CSRF validation failed"),
            Microsoft.IdentityModel.Tokens.SecurityTokenExpiredException => (StatusCodes.Status401Unauthorized, "Token expired"),
            Microsoft.IdentityModel.Tokens.SecurityTokenValidationException => (StatusCodes.Status401Unauthorized, "Token validation failed"),
            OperationCanceledException => (StatusCodes.Status400BadRequest, "Request cancelled"),
            _ => (StatusCodes.Status500InternalServerError, "Internal Server Error")
        };

        // Check if response has already started before making any modifications
        if (context.Response.HasStarted)
        {
            _logger.LogWarning("Response already started, cannot modify headers/body for: {Url}", context.Request.GetDisplayUrl());
            return;
        }

        // Clear authentication cookies for 401/403 responses
        if (statusCode is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
        {
            ClearAuthenticationCookies(context);
        }

        // Create ProblemDetails manually for consistent formatting
        var problemDetails = new ProblemDetails
        {
            Title = title,
            Status = statusCode,
            Detail = _environment.IsDevelopment() ? exception.Message : null,
            Instance = context.Request.Path,
            Type = GetProblemType(statusCode),
        };

        // Add custom extensions for specific exceptions
        if (exception is DomainValidationException domainValidationException)
        {
            problemDetails.Extensions["errors"] = domainValidationException.Errors;
        }

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";

        await JsonSerializer.SerializeAsync(context.Response.Body, problemDetails, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
    }
}
