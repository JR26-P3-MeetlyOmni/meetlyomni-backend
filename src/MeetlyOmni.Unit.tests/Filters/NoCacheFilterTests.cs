// <copyright file="NoCacheFilterTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Filters;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;

using Xunit;

namespace MeetlyOmni.Unit.tests.Filters;

/// <summary>
/// Tests for <see cref="NoCacheFilter"/>.
/// </summary>
public class NoCacheFilterTests
{
    private readonly NoCacheFilter _filter;

    public NoCacheFilterTests()
    {
        _filter = new NoCacheFilter();
    }

    [Fact]
    public void OnResultExecuted_WithObjectResult_ShouldSetNoCacheHeaders()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var result = new OkObjectResult(new { message = "test" });
        var context = new ResultExecutedContext(actionContext, new List<IFilterMetadata>(), result, httpContext);

        // Act
        _filter.OnResultExecuted(context);

        // Assert
        httpContext.Response.Headers["Cache-Control"].ToString().Should().Be("no-store, no-cache, must-revalidate, max-age=0");
        httpContext.Response.Headers["Pragma"].ToString().Should().Be("no-cache");
        httpContext.Response.Headers["Expires"].ToString().Should().Be("0");
    }

    [Fact]
    public void OnResultExecuted_WithNonObjectResult_ShouldNotSetNoCacheHeaders()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var result = new NotFoundResult();
        var context = new ResultExecutedContext(actionContext, new List<IFilterMetadata>(), result, httpContext);

        // Act
        _filter.OnResultExecuted(context);

        // Assert
        httpContext.Response.Headers.Should().NotContainKey("Cache-Control");
        httpContext.Response.Headers.Should().NotContainKey("Pragma");
        httpContext.Response.Headers.Should().NotContainKey("Expires");
    }

    [Fact]
    public void OnResultExecuted_WithExistingHeaders_ShouldOverrideCacheHeaders()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["Cache-Control"] = "public, max-age=3600";
        httpContext.Response.Headers["Pragma"] = "cache";
        httpContext.Response.Headers["Expires"] = "Wed, 21 Oct 2025 07:28:00 GMT";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var result = new OkObjectResult(new { message = "test" });
        var context = new ResultExecutedContext(actionContext, new List<IFilterMetadata>(), result, httpContext);

        // Act
        _filter.OnResultExecuted(context);

        // Assert
        httpContext.Response.Headers["Cache-Control"].ToString().Should().Be("no-store, no-cache, must-revalidate, max-age=0");
        httpContext.Response.Headers["Pragma"].ToString().Should().Be("no-cache");
        httpContext.Response.Headers["Expires"].ToString().Should().Be("0");
    }

    [Fact]
    public void OnResultExecuted_ShouldPreserveOtherHeaders()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["Content-Type"] = "application/json";
        httpContext.Response.Headers["X-Custom-Header"] = "custom-value";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var result = new OkObjectResult(new { message = "test" });
        var context = new ResultExecutedContext(actionContext, new List<IFilterMetadata>(), result, httpContext);

        // Act
        _filter.OnResultExecuted(context);

        // Assert
        httpContext.Response.Headers["Content-Type"].ToString().Should().Be("application/json");
        httpContext.Response.Headers["X-Custom-Header"].ToString().Should().Be("custom-value");
    }
}
