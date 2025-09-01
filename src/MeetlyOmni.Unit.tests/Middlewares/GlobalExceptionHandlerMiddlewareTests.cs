// <copyright file="GlobalExceptionHandlerMiddlewareTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Middlewares;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace MeetlyOmni.Unit.tests.Middlewares;

/// <summary>
/// Tests for <see cref="GlobalExceptionHandlerMiddleware"/>.
/// </summary>
public class GlobalExceptionHandlerMiddlewareTests
{
    private readonly Mock<ILogger<GlobalExceptionHandlerMiddleware>> _mockLogger;
    private readonly Mock<IWebHostEnvironment> _mockEnvironment;
    private readonly GlobalExceptionHandlerMiddleware _middleware;

    public GlobalExceptionHandlerMiddlewareTests()
    {
        _mockLogger = new Mock<ILogger<GlobalExceptionHandlerMiddleware>>();
        _mockEnvironment = new Mock<IWebHostEnvironment>();
        _middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new Exception("Test exception"),
            _mockLogger.Object,
            _mockEnvironment.Object);
    }

    [Fact]
    public async Task InvokeAsync_WithUnauthorizedAppException_ShouldReturn401()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new UnauthorizedAppException("Unauthorized access"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Unauthorized");
    }

    [Fact]
    public async Task InvokeAsync_WithDomainValidationException_ShouldReturn400()
    {
        // Arrange
        var validationErrors = new Dictionary<string, string[]>
        {
            { "Email", new[] { "Email is required" } },
            { "Password", new[] { "Password is required" } }
        };

        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new DomainValidationException(validationErrors, "Validation failed"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Validation failed");
        responseBody.Should().Contain("Email is required");
    }

    [Fact]
    public async Task InvokeAsync_WithEntityNotFoundException_ShouldReturn404()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new EntityNotFoundException("User", "123", "User not found"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status404NotFound);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Not found");
    }

    [Fact]
    public async Task InvokeAsync_WithConflictAppException_ShouldReturn409()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new ConflictAppException("Resource conflict"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status409Conflict);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Conflict");
    }

    [Fact]
    public async Task InvokeAsync_WithForbiddenAppException_ShouldReturn403()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new ForbiddenAppException("Access forbidden"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Forbidden");
    }

    [Fact]
    public async Task InvokeAsync_WithGenericException_ShouldReturn500()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new InvalidOperationException("Something went wrong"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
        httpContext.Response.ContentType.Should().StartWith("application/problem+json");

        httpContext.Response.Body.Position = 0;
        var responseBody = await new StreamReader(httpContext.Response.Body).ReadToEndAsync();
        responseBody.Should().Contain("Internal Server Error");
    }

    [Fact]
    public async Task InvokeAsync_WithUnauthorizedException_ShouldClearAuthenticationCookies()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => throw new UnauthorizedAppException("Unauthorized"),
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);

        // Check that cookies are cleared (expired)
        var setCookieHeaders = httpContext.Response.Headers["Set-Cookie"].ToString();
        setCookieHeaders.Should().Contain("access_token");
        setCookieHeaders.Should().Contain("refresh_token");
        setCookieHeaders.Should().Contain("expires=Thu, 01 Jan 1970");
    }

    [Fact]
    public async Task InvokeAsync_WithNoException_ShouldNotModifyResponse()
    {
        // Arrange
        var middleware = new GlobalExceptionHandlerMiddleware(
            next: (context) => Task.CompletedTask,
            _mockLogger.Object,
            _mockEnvironment.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.StatusCode = 200;

        // Act
        await middleware.InvokeAsync(httpContext);

        // Assert
        httpContext.Response.StatusCode.Should().Be(200);
    }


}
