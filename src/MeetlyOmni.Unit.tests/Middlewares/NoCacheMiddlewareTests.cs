// <copyright file="NoCacheMiddlewareTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Middlewares;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Moq;

namespace MeetlyOmni.Unit.tests.Middlewares;

public class NoCacheMiddlewareTests
{
    private readonly Mock<ILogger<NoCacheMiddleware>> _loggerMock;
    private readonly NoCacheMiddleware _middleware;

    public NoCacheMiddlewareTests()
    {
        _loggerMock = new Mock<ILogger<NoCacheMiddleware>>();
        var nextMock = new Mock<RequestDelegate>();
        nextMock.Setup(x => x(It.IsAny<HttpContext>())).Returns(Task.CompletedTask);
        _middleware = new NoCacheMiddleware(nextMock.Object, _loggerMock.Object);
    }

    [Fact]
    public async Task InvokeAsync_AuthenticationEndpoint_ShouldApplyNoCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/login";
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store, no-cache, must-revalidate, max-age=0");
        context.Response.Headers.Pragma.ToString().Should().Be("no-cache");
        context.Response.Headers.Expires.ToString().Should().Be("0");
    }

    [Fact]
    public async Task InvokeAsync_NonAuthenticationEndpoint_ShouldNotApplyCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/users";
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
        context.Response.Headers.Pragma.Should().BeEmpty();
        context.Response.Headers.Expires.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_NonJsonResponse_ShouldNotApplyCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/login";
        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/html";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_Non200Response_ShouldNotApplyCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/login";
        context.Response.StatusCode = 400;
        context.Response.ContentType = "application/json";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
    }

    [Theory]
    [InlineData("/api/v1/auth/login")]
    [InlineData("/api/v1/auth/refresh")]
    [InlineData("/api/v1/auth/logout")]
    [InlineData("/api/v1/auth/csrf")]
    [InlineData("/api/v2/auth/login")]
    [InlineData("/api/v2/auth/refresh")]
    public async Task InvokeAsync_VariousAuthEndpoints_ShouldApplyNoCacheHeaders(string path)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store, no-cache, must-revalidate, max-age=0");
        context.Response.Headers.Pragma.ToString().Should().Be("no-cache");
        context.Response.Headers.Expires.ToString().Should().Be("0");
    }

    [Theory]
    [InlineData("/api/v1/users")]
    [InlineData("/api/v1/products")]
    [InlineData("/api/v1/orders")]
    [InlineData("/api/v2/users")]
    public async Task InvokeAsync_NonAuthEndpoints_ShouldNotApplyCacheHeaders(string path)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
        context.Response.Headers.Pragma.Should().BeEmpty();
        context.Response.Headers.Expires.Should().BeEmpty();
    }
}
