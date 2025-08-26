// <copyright file="LoginControllerTestsSimple.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

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
/// Unit tests for LoginController following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class LoginControllerTests
{
    private readonly Mock<ILoginService> _mockLoginService;
    private readonly Mock<IClientInfoService> _mockClientInfoService;
    private readonly Mock<ILogger<LoginController>> _mockLogger;
    private readonly LoginController _loginController;

    public LoginControllerTests()
    {
        // Arrange - Common setup for all tests
        _mockLoginService = new Mock<ILoginService>();
        _mockClientInfoService = new Mock<IClientInfoService>();
        _mockLogger = MockHelper.CreateMockLogger<LoginController>();

        _loginController = new LoginController(_mockLoginService.Object, _mockClientInfoService.Object, _mockLogger.Object);

        // Configure HttpContext with required services
        SetupHttpContext();
    }

    [Fact]
    public async Task Login_WithValidRequest_ShouldCallLoginService()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedResponse = new InternalLoginResponse
        {
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
            AccessToken = "test-access-token",
            RefreshToken = "test-refresh-token"
        };

        _mockLoginService
            .Setup(x => x.LoginAsync(loginRequest, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(expectedResponse);

        // Act
        var result = await _loginController.Login(loginRequest);

        // Assert
        _mockLoginService.Verify(
            x => x.LoginAsync(loginRequest, It.IsAny<string>(), It.IsAny<string>()),
            Times.Once);
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task Login_WithInvalidModelState_ShouldReturnValidationProblem()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateInvalidLoginRequest();
        _loginController.ModelState.AddModelError("Email", "Email is required");

        // Act
        var result = await _loginController.Login(loginRequest);

        // Assert
        result.Should().BeAssignableTo<IActionResult>();
    }

    [Fact]
    public async Task Login_WhenLoginServiceThrowsUnauthorizedAccessException_ShouldReturnUnauthorizedProblem()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exceptionMessage = "Invalid credentials.";

        _mockLoginService
            .Setup(x => x.LoginAsync(loginRequest, It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new UnauthorizedAccessException(exceptionMessage));

        // Act
        var result = await _loginController.Login(loginRequest);

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails.Should().NotBeNull();
        problemDetails!.Title.Should().Be("Authentication Failed");
        problemDetails.Detail.Should().Be(exceptionMessage);
    }

    [Fact]
    public async Task Login_ShouldPassCorrectRequestToLoginService()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedResponse = new InternalLoginResponse
        {
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
            AccessToken = "test-access-token",
            RefreshToken = "test-refresh-token"
        };

        _mockLoginService
            .Setup(x => x.LoginAsync(It.IsAny<LoginRequest>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(expectedResponse);

        // Act
        await _loginController.Login(loginRequest);

        // Assert
        _mockLoginService.Verify(
            x => x.LoginAsync(
                It.Is<LoginRequest>(r =>
                    r.Email == loginRequest.Email &&
                    r.Password == loginRequest.Password),
                It.IsAny<string>(),
                It.IsAny<string>()),
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

        // Build the service provider
        var serviceProvider = services.BuildServiceProvider();

        // Create HttpContext with the configured service provider
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Set the HttpContext on the controller
        _loginController.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }
}
