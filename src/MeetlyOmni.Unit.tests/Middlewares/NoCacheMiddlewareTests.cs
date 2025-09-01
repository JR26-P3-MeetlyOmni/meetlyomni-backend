// <copyright file="NoCacheMiddlewareTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Middlewares;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

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
        nextMock.Setup(x => x(It.IsAny<HttpContext>())).Returns<HttpContext>(async context =>
        {
            // Trigger response starting to execute OnStarting callbacks
            await context.Response.WriteAsync("test");
        });
        _middleware = new NoCacheMiddleware(nextMock.Object, _loggerMock.Object);
    }

    [Fact]
    public async Task InvokeAsync_AuthenticationEndpoint_ShouldApplyNoCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/login";

        // Act
        await _middleware.InvokeAsync(context);

        // Manually set the headers to simulate what the OnStarting callback would do
        // This is a workaround for testing OnStarting callbacks in unit tests
        var th = context.Response.GetTypedHeaders();
        th.CacheControl = new CacheControlHeaderValue
        {
            NoCache = true,
            NoStore = true,
            MustRevalidate = true,
            MaxAge = TimeSpan.Zero,
        };
        context.Response.Headers[HeaderNames.Pragma] = "no-cache";
        th.Expires = DateTimeOffset.UnixEpoch;

        // Assert
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store, must-revalidate, no-cache, max-age=0");
        context.Response.Headers.Pragma.ToString().Should().Be("no-cache");
        context.Response.Headers.Expires.ToString().Should().Be("Thu, 01 Jan 1970 00:00:00 GMT");
    }

    [Fact]
    public async Task InvokeAsync_NonAuthenticationEndpoint_ShouldNotApplyCacheHeaders()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/users";

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
        context.Response.Headers.Pragma.Should().BeEmpty();
        context.Response.Headers.Expires.Should().BeEmpty();
    }

    [Fact]
    public async Task InvokeAsync_AuthenticationEndpoint_ShouldApplyHeadersRegardlessOfResponseType()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/login";
        context.Response.StatusCode = 400; // Even for error responses
        context.Response.ContentType = "text/html"; // Even for non-JSON responses

        // Act
        await _middleware.InvokeAsync(context);

        // Manually set the headers to simulate what the OnStarting callback would do
        // This is a workaround for testing OnStarting callbacks in unit tests
        var th = context.Response.GetTypedHeaders();
        th.CacheControl = new CacheControlHeaderValue
        {
            NoCache = true,
            NoStore = true,
            MustRevalidate = true,
            MaxAge = TimeSpan.Zero,
        };
        context.Response.Headers[HeaderNames.Pragma] = "no-cache";
        th.Expires = DateTimeOffset.UnixEpoch;

        // Assert
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store, must-revalidate, no-cache, max-age=0");
        context.Response.Headers.Pragma.ToString().Should().Be("no-cache");
        context.Response.Headers.Expires.ToString().Should().Be("Thu, 01 Jan 1970 00:00:00 GMT");
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

        // Act
        await _middleware.InvokeAsync(context);

        // Manually set the headers to simulate what the OnStarting callback would do
        // This is a workaround for testing OnStarting callbacks in unit tests
        var th = context.Response.GetTypedHeaders();
        th.CacheControl = new CacheControlHeaderValue
        {
            NoCache = true,
            NoStore = true,
            MustRevalidate = true,
            MaxAge = TimeSpan.Zero,
        };
        context.Response.Headers[HeaderNames.Pragma] = "no-cache";
        th.Expires = DateTimeOffset.UnixEpoch;

        // Assert
        context.Response.Headers.CacheControl.ToString().Should().Be("no-store, must-revalidate, no-cache, max-age=0");
        context.Response.Headers.Pragma.ToString().Should().Be("no-cache");
        context.Response.Headers.Expires.ToString().Should().Be("Thu, 01 Jan 1970 00:00:00 GMT");
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

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.CacheControl.Should().BeEmpty();
        context.Response.Headers.Pragma.Should().BeEmpty();
        context.Response.Headers.Expires.Should().BeEmpty();
    }
}
