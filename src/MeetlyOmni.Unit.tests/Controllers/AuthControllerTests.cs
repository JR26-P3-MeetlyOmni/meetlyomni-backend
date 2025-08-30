// <copyright file="AuthControllerTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using FluentAssertions;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Api.Filters;
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
/// Tests for <see cref="AuthController"/>.
/// </summary>
public class AuthControllerTests
{
    private readonly AuthController _authController;
    private readonly Mock<ILoginService> _mockLoginService;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IClientInfoService> _mockClientInfoService;
    private readonly Mock<IAntiforgery> _mockAntiforgery;
    private readonly Mock<ILogger<AuthController>> _mockLogger;

    public AuthControllerTests()
    {
        _mockLoginService = new Mock<ILoginService>();
        _mockTokenService = new Mock<ITokenService>();
        _mockClientInfoService = new Mock<IClientInfoService>();
        _mockAntiforgery = new Mock<IAntiforgery>();
        _mockLogger = new Mock<ILogger<AuthController>>();

        _authController = new AuthController(
            _mockLoginService.Object,
            _mockTokenService.Object,
            _mockClientInfoService.Object,
            _mockAntiforgery.Object,
            _mockLogger.Object);

        SetupHttpContext();
    }

    [Fact]
    public async Task LoginAsync_WithValidRequest_ShouldReturnOk()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedResponse = new InternalLoginResponse
        {
            AccessToken = "test-access-token",
            RefreshToken = "test-refresh-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            RefreshTokenExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            TokenType = "Bearer"
        };

        _mockClientInfoService
            .Setup(x => x.GetClientInfo(It.IsAny<HttpContext>()))
            .Returns(("TestUserAgent", "127.0.0.1"));

        _mockLoginService
            .Setup(x => x.LoginAsync(loginRequest, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedResponse);

        // Act
        var result = await _authController.LoginAsync(loginRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        var response = okResult!.Value as LoginResponse;
        response!.AccessToken.Should().Be(expectedResponse.AccessToken);
        response.ExpiresAt.Should().Be(expectedResponse.ExpiresAt);
        response.TokenType.Should().Be(expectedResponse.TokenType);
    }

    [Fact]
    public async Task LoginAsync_WhenLoginServiceThrowsUnauthorizedAppException_ShouldThrowException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exceptionMessage = "Invalid credentials.";

        _mockLoginService
            .Setup(x => x.LoginAsync(loginRequest, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new UnauthorizedAppException(exceptionMessage));

        // Act & Assert
        var act = () => _authController.LoginAsync(loginRequest, CancellationToken.None);

        await act.Should().ThrowAsync<UnauthorizedAppException>()
            .WithMessage(exceptionMessage);
    }

    [Fact]
    public void GetCsrf_ShouldReturnOk()
    {
        // Arrange
        var tokens = new AntiforgeryTokenSet("request-token", "cookie-token", "form-field-name", "header-name");
        _mockAntiforgery
            .Setup(x => x.GetAndStoreTokens(It.IsAny<HttpContext>()))
            .Returns(tokens);

        // Act
        var result = _authController.GetCsrf();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(new { message = "CSRF token generated" });
    }

    [Fact]
    public async Task RefreshTokenAsync_WithValidToken_ShouldReturnOk()
    {
        // Arrange
        var refreshToken = "valid-refresh-token";
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";
        var expectedTokens = new TokenResult(
            "new-access-token",
            DateTimeOffset.UtcNow.AddHours(1),
            "new-refresh-token",
            DateTimeOffset.UtcNow.AddDays(30));

        // Add refresh token to cookies
        _authController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

        // Setup client info service
        _mockClientInfoService
            .Setup(x => x.GetClientInfo(It.IsAny<HttpContext>()))
            .Returns((userAgent, ipAddress));

        _mockTokenService
            .Setup(x => x.RefreshTokenPairAsync(refreshToken, userAgent, ipAddress, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedTokens);

        // Act
        var result = await _authController.RefreshTokenAsync(CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        var response = okResult!.Value as LoginResponse;
        response!.AccessToken.Should().Be(expectedTokens.accessToken);
        response.ExpiresAt.Should().Be(expectedTokens.accessTokenExpiresAt);
        response.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task RefreshTokenAsync_WithMissingToken_ShouldThrowException()
    {
        // Arrange
        // Don't add any refresh token to cookies

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

        // Act & Assert
        var act = () => _authController.RefreshTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<UnauthorizedAppException>()
            .WithMessage("Refresh token is missing.");
    }

    [Fact]
    public async Task RefreshTokenAsync_WithInvalidRefreshToken_ShouldThrowException()
    {
        // Arrange
        var refreshToken = "invalid-refresh-token";
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";

        // Add refresh token to cookies
        _authController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to succeed
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .Returns(Task.CompletedTask);

        // Setup client info service
        _mockClientInfoService
            .Setup(x => x.GetClientInfo(It.IsAny<HttpContext>()))
            .Returns((userAgent, ipAddress));

        _mockTokenService
            .Setup(x => x.RefreshTokenPairAsync(refreshToken, userAgent, ipAddress, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new UnauthorizedAppException("Invalid refresh token"));

        // Act & Assert
        var act = () => _authController.RefreshTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<UnauthorizedAppException>()
            .WithMessage("Invalid refresh token");
    }

    [Fact]
    public async Task RefreshTokenAsync_WithAntiforgeryValidationFailure_ShouldThrowException()
    {
        // Arrange
        var refreshToken = "test-refresh-token";

        // Add refresh token to cookies
        _authController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup antiforgery validation to fail
        _mockAntiforgery
            .Setup(x => x.ValidateRequestAsync(It.IsAny<HttpContext>()))
            .ThrowsAsync(new AntiforgeryValidationException("Antiforgery validation failed"));

        // Act & Assert
        var act = () => _authController.RefreshTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<AntiforgeryValidationException>()
            .WithMessage("Antiforgery validation failed");
    }

    [Fact]
    public void GetCurrentUser_ShouldReturnOk()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtClaimTypes.Subject, "test-user-id"),
            new(JwtClaimTypes.Email, "test@example.com"),
            new(JwtClaimTypes.OrganizationId, "test-org-id")
        };

        _authController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        // Act
        var result = _authController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        var response = okResult!.Value;

        // Use reflection to access the anonymous type properties
        var userId = response.GetType().GetProperty("userId")?.GetValue(response);
        var email = response.GetType().GetProperty("email")?.GetValue(response);
        var orgId = response.GetType().GetProperty("orgId")?.GetValue(response);

        userId.Should().Be("test-user-id");
        email.Should().Be("test@example.com");
        orgId.Should().Be("test-org-id");
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

        // Set up request headers and cookies
        httpContext.Request.Headers["User-Agent"] = "TestUserAgent";
        httpContext.Request.Headers["X-Forwarded-For"] = "192.168.1.1";

        // Set the HttpContext on the controller
        _authController.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }
    // ---------------------------
    // LogoutAsync Tests
    // ---------------------------

    [Fact]
    public async Task LogoutAsync_WithValidUserAndRefreshToken_ShouldCallTokenServiceAndClearCookies()
    {
        // Arrange
        var refreshToken = "refresh-token-to-logout";

        var mockCookies = new Mock<IRequestCookieCollection>();
        mockCookies
            .Setup(c => c.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out refreshToken))
            .Returns(true);
        mockCookies
            .Setup(c => c[AuthCookieExtensions.CookieNames.RefreshToken])
            .Returns(refreshToken);

        _authController.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                Request = { Cookies = mockCookies.Object }
            }
        };

        _mockTokenService
            .Setup(x => x.LogoutAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _authController.LogoutAsync(CancellationToken.None);

        // Assert
        _mockTokenService.Verify(x => x.LogoutAsync(refreshToken, It.IsAny<CancellationToken>()), Times.Once);

        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(new { message = "Logged out successfully" });
    }

    [Fact]
    public async Task LogoutAsync_WithoutRefreshToken_ShouldReturnUnauthorized()
    {
        // Arrange
        var mockCookies = new Mock<IRequestCookieCollection>();
        mockCookies.Setup(c => c[AuthCookieExtensions.CookieNames.RefreshToken]).Returns<string?>(null);
        _authController.HttpContext.Request.Cookies = mockCookies.Object;

        var claims = new List<Claim>
    {
        new Claim(JwtClaimTypes.Subject, Guid.NewGuid().ToString())
    };
        _authController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "mock"));

        // Act
        var result = await _authController.LogoutAsync(CancellationToken.None);

        // Assert
        _mockTokenService.Verify(x => x.LogoutAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);

        result.Should().BeOfType<UnauthorizedObjectResult>();
        var unauthorizedResult = result as UnauthorizedObjectResult;
        unauthorizedResult!.Value.Should().BeEquivalentTo(new { message = "Refresh token missing" });
    }

    [Fact]
    public async Task LogoutAsync_WithInvalidRefreshToken_ShouldReturnUnauthorized()
    {
        // Arrange
        var refreshToken = "invalid-refresh-token";

        var mockCookies = new Mock<IRequestCookieCollection>();
        mockCookies
            .Setup(c => c.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out refreshToken))
            .Returns(true);
        mockCookies
            .Setup(c => c[AuthCookieExtensions.CookieNames.RefreshToken])
            .Returns(refreshToken);

        _authController.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                Request = { Cookies = mockCookies.Object }
            }
        };

        _mockTokenService
            .Setup(x => x.LogoutAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        var result = await _authController.LogoutAsync(CancellationToken.None);

        // Assert
        _mockTokenService.Verify(x => x.LogoutAsync(refreshToken, It.IsAny<CancellationToken>()), Times.Once);

        result.Should().BeOfType<UnauthorizedObjectResult>();
        var unauthorizedResult = result as UnauthorizedObjectResult;
        unauthorizedResult!.Value.Should().BeEquivalentTo(new { message = "Invalid or expired refresh token" });
    }

    [Fact]
    public async Task LogoutAsync_WhenServiceThrows_ShouldReturnInternalServerError()
    {
        // Arrange
        var refreshToken = "refresh-token-to-logout";

        var mockCookies = new Mock<IRequestCookieCollection>();
        mockCookies
            .Setup(c => c.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out refreshToken))
            .Returns(true);
        mockCookies
            .Setup(c => c[AuthCookieExtensions.CookieNames.RefreshToken])
            .Returns(refreshToken);

        _authController.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
            {
                Request = { Cookies = mockCookies.Object }
            }
        };

        _mockTokenService
            .Setup(x => x.LogoutAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Unexpected error"));

        // Act
        Func<Task> act = async () => await _authController.LogoutAsync(CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<Exception>().WithMessage("Unexpected error");
    }

}
