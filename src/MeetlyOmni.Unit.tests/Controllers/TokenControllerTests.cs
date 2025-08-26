// <copyright file="TokenControllerTestsSimple.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using FluentAssertions;

using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace MeetlyOmni.Unit.tests.Controllers;

/// <summary>
/// Unit tests for TokenController following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class TokenControllerTests
{
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IClientInfoService> _mockClientInfoService;
    private readonly Mock<ILogger<TokenController>> _mockLogger;
    private readonly TokenController _tokenController;

    public TokenControllerTests()
    {
        // Arrange - Common setup for all tests
        _mockTokenService = new Mock<ITokenService>();
        _mockClientInfoService = new Mock<IClientInfoService>();
        _mockLogger = MockHelper.CreateMockLogger<TokenController>();

        _tokenController = new TokenController(_mockTokenService.Object, _mockClientInfoService.Object, _mockLogger.Object);

        // Setup HttpContext for cookie operations
        var httpContext = new DefaultHttpContext();
        _tokenController.ControllerContext = new ControllerContext()
        {
            HttpContext = httpContext
        };
    }

    [Fact]
    public async Task RefreshToken_WithValidRefreshToken_ShouldCallTokenService()
    {
        // Arrange
        var refreshToken = "valid-refresh-token";
        var expectedTokenResult = new TokenResult(
            "new-access-token",
            DateTimeOffset.UtcNow.AddMinutes(15),
            "new-refresh-token",
            DateTimeOffset.UtcNow.AddDays(7)
        );

        // Add refresh token to cookies
        _tokenController.HttpContext.Request.Headers.Cookie = $"refresh_token={refreshToken}";

        _mockTokenService
            .Setup(x => x.RefreshTokenPairAsync(refreshToken, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(expectedTokenResult);

        // Act
        var result = await _tokenController.RefreshToken();

        // Assert
        _mockTokenService.Verify(
            x => x.RefreshTokenPairAsync(refreshToken, It.IsAny<string>(), It.IsAny<string>()),
            Times.Once);
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task RefreshToken_WithMissingRefreshToken_ShouldReturnUnauthorized()
    {
        // Arrange - No refresh token in cookies

        // Act
        var result = await _tokenController.RefreshToken();

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails.Should().NotBeNull();
        problemDetails!.Title.Should().Be("Refresh Token Missing");
        problemDetails.Detail.Should().Be("Refresh token not found in request");
    }

    [Fact]
    public async Task RefreshToken_WithInvalidRefreshToken_ShouldReturnUnauthorized()
    {
        // Arrange
        var invalidRefreshToken = "invalid-refresh-token";

        _tokenController.HttpContext.Request.Headers.Cookie = $"refresh_token={invalidRefreshToken}";

        _mockTokenService
            .Setup(x => x.RefreshTokenPairAsync(invalidRefreshToken, It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new UnauthorizedAccessException("Invalid refresh token"));

        // Act
        var result = await _tokenController.RefreshToken();

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails.Should().NotBeNull();
        problemDetails!.Title.Should().Be("Token Refresh Failed");
        problemDetails.Detail.Should().Be("Invalid refresh token");
    }

    [Fact]
    public async Task RefreshToken_ShouldPassCorrectParametersToTokenService()
    {
        // Arrange
        var refreshToken = "test-refresh-token";
        var expectedTokenResult = new TokenResult(
            "new-access-token",
            DateTimeOffset.UtcNow.AddMinutes(15),
            "new-refresh-token",
            DateTimeOffset.UtcNow.AddDays(7)
        );

        _tokenController.HttpContext.Request.Headers.Cookie = $"refresh_token={refreshToken}";

        _mockTokenService
            .Setup(x => x.RefreshTokenPairAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(expectedTokenResult);

        // Act
        await _tokenController.RefreshToken();

        // Assert
        _mockTokenService.Verify(
            x => x.RefreshTokenPairAsync(
                refreshToken,
                It.IsAny<string>(), // User agent
                It.IsAny<string>()), // IP address
            Times.Once);
    }

    // ---------------------------
    // Logout Tests
    // ---------------------------

    [Fact]
    public async Task Logout_WithValidUser_ShouldCallTokenServiceAndClearCookies()
    {
        // Arrange
        var refreshToken = "refresh-token-to-logout";

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = $"refresh_token={refreshToken}";

        _tokenController.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        // Act
        var result = await _tokenController.Logout();

        // Assert
        _mockTokenService.Verify(x => x.LogoutAsync(refreshToken), Times.Once);

        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(new { message = "Logged out successfully" });

        _tokenController.HttpContext.Response.Cookies.Should().NotBeNull();
    }

    [Fact]
    public async Task Logout_WithNoUserId_ShouldSkipTokenServiceAndStillClearCookies()
    {
        // Arrange - No claims in user principal
        _tokenController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        var result = await _tokenController.Logout();

        // Assert
        _mockTokenService.Verify(x => x.LogoutAsync(It.IsAny<string>()), Times.Never);

        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(new { message = "Logged out successfully" });
    }

    [Fact]
    public async Task Logout_WhenServiceThrows_ShouldReturnProblemResult()
    {
        // Arrange
        var refreshToken = "refresh-token-to-logout";

        _mockTokenService
            .Setup(x => x.LogoutAsync(refreshToken))
            .ThrowsAsync(new Exception("Unexpected error"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = $"refresh_token={refreshToken}";

        _tokenController.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };

        // Act
        var result = await _tokenController.Logout();

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails!.Title.Should().Be("Internal Server Error");
        problemDetails.Detail.Should().Be("An unexpected error occurred during logout");
    }
}
