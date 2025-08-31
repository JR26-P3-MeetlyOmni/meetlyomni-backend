// <copyright file="RefreshTokenValidationFilterTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Filters;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;

using Xunit;

namespace MeetlyOmni.Unit.tests.Filters;

/// <summary>
/// Tests for <see cref="RefreshTokenValidationFilter"/>.
/// </summary>
public class RefreshTokenValidationFilterTests
{
    private readonly RefreshTokenValidationFilter _filter;

    public RefreshTokenValidationFilterTests()
    {
        _filter = new RefreshTokenValidationFilter();
    }

    [Fact]
    public void OnActionExecuting_WithValidRefreshToken_ShouldNotThrowException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}=valid-refresh-token";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act
        var act = () => _filter.OnActionExecuting(context);

        // Assert
        act.Should().NotThrow();
        context.Result.Should().BeNull();
    }

    [Fact]
    public void OnActionExecuting_WithMissingRefreshToken_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        // No cookies set

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act & Assert
        var act = () => _filter.OnActionExecuting(context);

        act.Should().Throw<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }

    [Fact]
    public void OnActionExecuting_WithEmptyRefreshToken_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}=";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act & Assert
        var act = () => _filter.OnActionExecuting(context);

        act.Should().Throw<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }

    [Fact]
    public void OnActionExecuting_WithWhitespaceRefreshToken_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}=   ";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act & Assert
        var act = () => _filter.OnActionExecuting(context);

        act.Should().Throw<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }

    [Fact]
    public void OnActionExecuting_WithNullRefreshToken_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}=";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act & Assert
        var act = () => _filter.OnActionExecuting(context);

        act.Should().Throw<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }

    [Fact]
    public void OnActionExecuting_WithOtherCookiesButNoRefreshToken_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = "other-cookie=some-value; access_token=some-access-token";

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        var context = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object?>(), null!);

        // Act & Assert
        var act = () => _filter.OnActionExecuting(context);

        act.Should().Throw<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }
}
