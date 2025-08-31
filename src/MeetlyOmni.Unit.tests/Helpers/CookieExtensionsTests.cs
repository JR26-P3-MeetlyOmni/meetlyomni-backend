// <copyright file="CookieExtensionsTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Common.Extensions;

using Microsoft.AspNetCore.Http;

namespace MeetlyOmni.Unit.tests.Helpers;

public class CookieExtensionsTests
{
    [Fact]
    public void SetAccessTokenCookie_ShouldSetCookieWithCorrectOptions()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var token = "test-access-token";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        // Act
        context.Response.SetAccessTokenCookie(token, expiresAt);

        // Assert
        var setCookieHeader = context.Response.Headers["Set-Cookie"].ToString();
        setCookieHeader.Should().Contain("access_token=");
        setCookieHeader.Should().Contain("httponly");
        setCookieHeader.Should().Contain("secure");
        setCookieHeader.Should().Contain("samesite=none");
        setCookieHeader.Should().Contain("path=/");
    }

    [Fact]
    public void SetRefreshTokenCookie_ShouldSetCookieWithCorrectOptions()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var token = "test-refresh-token";
        var expiresAt = DateTimeOffset.UtcNow.AddDays(30);

        // Act
        context.Response.SetRefreshTokenCookie(token, expiresAt);

        // Assert
        var setCookieHeader = context.Response.Headers["Set-Cookie"].ToString();
        setCookieHeader.Should().Contain("refresh_token=");
        setCookieHeader.Should().Contain("httponly");
        setCookieHeader.Should().Contain("secure");
        setCookieHeader.Should().Contain("samesite=none");
        setCookieHeader.Should().Contain("path=/");
    }

    [Fact]
    public void DeleteAccessTokenCookie_ShouldDeleteCookieWithCorrectOptions()
    {
        // Arrange
        var context = new DefaultHttpContext();

        // Act
        context.Response.DeleteAccessTokenCookie();

        // Assert
        var setCookieHeader = context.Response.Headers["Set-Cookie"].ToString();
        setCookieHeader.Should().Contain("access_token=");
        setCookieHeader.Should().Contain("expires=Thu, 01 Jan 1970 00:00:00 GMT");
        setCookieHeader.Should().Contain("path=/");
    }

    [Fact]
    public void DeleteRefreshTokenCookie_ShouldDeleteCookieWithCorrectOptions()
    {
        // Arrange
        var context = new DefaultHttpContext();

        // Act
        context.Response.DeleteRefreshTokenCookie();

        // Assert
        var setCookieHeader = context.Response.Headers["Set-Cookie"].ToString();
        setCookieHeader.Should().Contain("refresh_token=");
        setCookieHeader.Should().Contain("expires=Thu, 01 Jan 1970 00:00:00 GMT");
        setCookieHeader.Should().Contain("path=/");
    }


}
