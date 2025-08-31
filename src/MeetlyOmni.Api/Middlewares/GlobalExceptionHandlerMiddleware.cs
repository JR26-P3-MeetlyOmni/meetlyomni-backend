// <copyright file="GlobalExceptionHandlerMiddleware.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json;

using MeetlyOmni.Api.Filters;

using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;

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

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        _logger.LogError(exception, "An unhandled exception occurred while processing request: {RequestUrl}", context.Request.GetDisplayUrl());

        var (statusCode, title) = exception switch
        {
            UnauthorizedAppException => (StatusCodes.Status401Unauthorized, "Unauthorized"),
            DomainValidationException => (StatusCodes.Status400BadRequest, "Validation failed"),
            EntityNotFoundException => (StatusCodes.Status404NotFound, "Not found"),
            ConflictAppException => (StatusCodes.Status409Conflict, "Conflict"),
            ForbiddenAppException => (StatusCodes.Status403Forbidden, "Forbidden"),
            _ => (StatusCodes.Status500InternalServerError, "Internal Server Error")
        };

        // Clear authentication cookies for unauthorized/forbidden errors
        if (statusCode == StatusCodes.Status401Unauthorized || statusCode == StatusCodes.Status403Forbidden)
        {
            ClearAuthenticationCookies(context);
        }

        var problemDetails = new ProblemDetails
        {
            Title = title,
            Status = statusCode,
            Detail = _environment.IsDevelopment() ? exception.Message : null,
            Instance = context.Request.Path,
            Type = GetProblemType(statusCode),
        };

        // Add additional details for validation errors
        if (exception is DomainValidationException validationEx)
        {
            problemDetails.Extensions["errors"] = validationEx.Errors;
        }

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";

        await JsonSerializer.SerializeAsync(context.Response.Body, problemDetails, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
    }

    private static void ClearAuthenticationCookies(HttpContext context)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/",
            Expires = DateTimeOffset.UnixEpoch,
        };

        context.Response.Cookies.Delete("access_token", cookieOptions);
        context.Response.Cookies.Delete("refresh_token", cookieOptions);
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
}
