// <copyright file="TokenControllerTestsSimple.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
    private readonly Mock<IAntiforgery> _mockAntiforgery;
    private readonly Mock<ILogger<TokenController>> _mockLogger;
    private readonly TokenController _tokenController;

    public TokenControllerTests()
    {
        // Arrange - Common setup for all tests
        _mockTokenService = new Mock<ITokenService>();
        _mockClientInfoService = new Mock<IClientInfoService>();
        _mockLogger = MockHelper.CreateMockLogger<TokenController>();

        _mockAntiforgery = new Mock<IAntiforgery>();
        _tokenController = new TokenController(_mockTokenService.Object, _mockClientInfoService.Object, _mockAntiforgery.Object, _mockLogger.Object);

        // Configure HttpContext with required services
        SetupHttpContext();
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
        _tokenController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

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
        // Arrange - No refresh token in cookies, but with antiforgery validation
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

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

        _tokenController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={invalidRefreshToken}";

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

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
        problemDetails.Detail.Should().Contain("Invalid refresh token");
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

        _tokenController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

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

    [Fact]
    public async Task RefreshToken_WithAntiforgeryValidationFailure_ShouldReturnInternalServerError()
    {
        // Arrange
        var refreshToken = "test-refresh-token";

        // Add refresh token to cookies
        _tokenController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to fail
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .ThrowsAsync(new InvalidOperationException("Antiforgery validation failed"));

        // Act
        var result = await _tokenController.RefreshToken();

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails.Should().NotBeNull();
        problemDetails!.Title.Should().Be("Internal Server Error");
    }

    private void SetupHttpContext()
    {
        // Create a service collection and add required services
        var services = new ServiceCollection();

        // Add MVC services (required for ProblemDetailsFactory and other controller dependencies)
        services.AddMvc();

        // Add IWebHostEnvironment as a mock or real implementation
        var mockEnvironment = new Mock<IWebHostEnvironment>();
        mockEnvironment.Setup(x => x.EnvironmentName).Returns("Production"); // Default to production for tests
        services.AddSingleton(mockEnvironment.Object);

        // Build the service provider
        var serviceProvider = services.BuildServiceProvider();

        // Create HttpContext with the configured service provider
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set the HttpContext on the controller
        _tokenController.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }
}
