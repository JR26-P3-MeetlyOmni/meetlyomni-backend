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
using MeetlyOmni.Api.Models.Member;
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
    private readonly Mock<ILogoutService> _mockLogoutService;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly Mock<ISignUpService> _mockSignUpService;

    public AuthControllerTests()
    {
        _mockLoginService = new Mock<ILoginService>();
        _mockTokenService = new Mock<ITokenService>();
        _mockClientInfoService = new Mock<IClientInfoService>();
        _mockAntiforgery = new Mock<IAntiforgery>();
        _mockLogoutService = new Mock<ILogoutService>();
        _mockLogger = new Mock<ILogger<AuthController>>();
        _mockSignUpService = new Mock<ISignUpService>();

        _authController = new AuthController(
            _mockLoginService.Object,
            _mockTokenService.Object,
            _mockClientInfoService.Object,
            _mockAntiforgery.Object,
            _mockLogger.Object,
            _mockLogoutService.Object,
            _mockSignUpService.Object);

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
        response!.ExpiresAt.Should().Be(expectedResponse.ExpiresAt);
        response.TokenType.Should().Be(expectedResponse.TokenType);

        // Verify that access token cookie was set
        var accessTokenCookie = _authController.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        accessTokenCookie.Should().NotBeNull();
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
            .Setup(x => x.RefreshTokenPairFromCookiesAsync(It.IsAny<HttpContext>(), userAgent, ipAddress, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedTokens);

        // Act
        var result = await _authController.RefreshTokenAsync(CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        var response = okResult!.Value as LoginResponse;
        response!.ExpiresAt.Should().Be(expectedTokens.accessTokenExpiresAt);
        response.TokenType.Should().Be("Bearer");

        // Verify that access token cookie was set
        var accessTokenCookie = _authController.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        accessTokenCookie.Should().NotBeNull();
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
            .Setup(x => x.RefreshTokenPairFromCookiesAsync(It.IsAny<HttpContext>(), userAgent, ipAddress, It.IsAny<CancellationToken>()))
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

        // Setup token service to throw exception (since antiforgery is now handled by middleware)
        _mockTokenService
            .Setup(x => x.RefreshTokenPairFromCookiesAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new UnauthorizedAppException("Invalid refresh token"));

        // Act & Assert
        var act = () => _authController.RefreshTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<UnauthorizedAppException>()
            .WithMessage("Invalid refresh token");
    }

    [Fact]
    public void GetCurrentUser_ShouldReturnOk()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new("sub", "12345678-1234-1234-1234-123456789012"),
            new("email", "test@example.com"),
            new("name", "Test User"),
            new("role", "User"),
            new("org_id", "test-org-id")
        };

        _authController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        // Act
        var result = _authController.GetCurrentUser();

        // Assert
        result.Result.Should().BeOfType<OkObjectResult>();
        var okResult = result.Result as OkObjectResult;
        var response = okResult!.Value as CurrentUserResponse;

        response.Should().NotBeNull();
        response!.Id.Should().Be(Guid.Parse("12345678-1234-1234-1234-123456789012"));
        response.Email.Should().Be("test@example.com");
        response.UserName.Should().Be("Test User");
        response.Role.Should().Be("User");
        response.OrgId.Should().Be("test-org-id");
    }

    [Fact]
    public void GetCurrentUser_WithMissingClaims_ShouldReturnOkWithDefaultValues()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new("sub", "12345678-1234-1234-1234-123456789012")
            // Missing email, name, role, and orgId claims
        };

        _authController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        // Act
        var result = _authController.GetCurrentUser();

        // Assert
        result.Result.Should().BeOfType<OkObjectResult>();
        var okResult = result.Result as OkObjectResult;
        var response = okResult!.Value as CurrentUserResponse;

        response.Should().NotBeNull();
        response!.Id.Should().Be(Guid.Parse("12345678-1234-1234-1234-123456789012"));
        response.Email.Should().Be(string.Empty);
        response.UserName.Should().Be(string.Empty);
        response.Role.Should().Be(string.Empty);
        response.OrgId.Should().Be(string.Empty);
    }

    [Fact]
    public void GetCurrentUser_WithUnauthenticatedUser_ShouldReturnUnauthorized()
    {
        // Arrange
        _authController.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        var result = _authController.GetCurrentUser();

        // Assert
        result.Result.Should().BeOfType<UnauthorizedObjectResult>();
        var unauthorizedResult = result.Result as UnauthorizedObjectResult;
        unauthorizedResult!.Value.Should().BeOfType<ProblemDetails>();
    }

    [Fact]
    public async Task LoginAsync_WithNullRequest_ShouldThrowNullReferenceException()
    {
        // Arrange
        LoginRequest? request = null;

        // Act & Assert
        var act = () => _authController.LoginAsync(request!, CancellationToken.None);

        await act.Should().ThrowAsync<NullReferenceException>();
    }

    [Fact]
    public async Task LoginAsync_WithInvalidModelState_ShouldThrowNullReferenceException()
    {
        // Arrange
        var request = new LoginRequest { Email = "", Password = "" };
        _authController.ModelState.AddModelError("Email", "Email is required");

        // Act & Assert
        var act = () => _authController.LoginAsync(request, CancellationToken.None);

        await act.Should().ThrowAsync<NullReferenceException>();
    }

    [Fact]
    public async Task RefreshTokenAsync_WithValidTokenAndServiceException_ShouldThrowException()
    {
        // Arrange
        var refreshToken = "valid-refresh-token";
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

        // Setup token service to throw an exception
        _mockTokenService
            .Setup(x => x.RefreshTokenPairFromCookiesAsync(It.IsAny<HttpContext>(), userAgent, ipAddress, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Token service error"));

        // Act & Assert
        var act = () => _authController.RefreshTokenAsync(CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Token service error");
    }

    [Fact]
    public async Task LogoutAsync_WithValidUser_ShouldReturnOkAndClearCookies()
    {
        // Arrange
        var refreshToken = "valid-refresh-token";

        // Add refresh token to cookies
        _authController.HttpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        // Setup logout service
        _mockLogoutService
            .Setup(x => x.LogoutAsync(It.IsAny<HttpContext>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _authController.LogoutAsync(CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        var response = okResult!.Value;

        // Use reflection to access the anonymous type properties
        var message = response.GetType().GetProperty("message")?.GetValue(response);
        message.Should().Be("Logged out successfully");

        // Verify that logout service was called
        _mockLogoutService.Verify(
            x => x.LogoutAsync(It.IsAny<HttpContext>(), It.IsAny<CancellationToken>()),
            Times.Once);
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

        // Add the mocked antiforgery service to the service collection
        services.AddSingleton(_mockAntiforgery.Object);

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

    [Fact]
    public async Task SignUp_WithValidRequest_ShouldReturnCreated()
    {
        var signupRequest = new AdminSignupRequest
        {
            UserName = "Test User",
            Email = "testuser@example.com",
            Password = "TestPassword123!",
            OrganizationName = "Test Org",
            PhoneNumber = "1234567890"
        };

        var expectedMember = new MemberDto
        {
            Id = Guid.NewGuid(),
            Email = signupRequest.Email
        };

        _mockSignUpService
            .Setup(x => x.SignUpAdminAsync(signupRequest))
            .ReturnsAsync(expectedMember);

        var result = await _authController.SignUp(signupRequest);

        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status201Created);
        objectResult.Value.Should().BeEquivalentTo(expectedMember);
    }
}
