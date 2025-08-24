// <copyright file="AuthControllerTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace MeetlyOmni.Unit.tests.Controllers;

/// <summary>
/// Unit tests for AuthController following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class AuthControllerTests
{
    private readonly Mock<IAuthService> _mockAuthService;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly AuthController _authController;

    public AuthControllerTests()
    {
        // Arrange - Common setup for all tests
        _mockAuthService = new Mock<IAuthService>();
        _mockLogger = MockHelper.CreateMockLogger<AuthController>();

        _authController = new AuthController(_mockAuthService.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task Login_WithValidRequest_ShouldReturnOkWithLoginResponse()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedResponse = new LoginResponse
        {
            AccessToken = "test-access-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
        };

        _mockAuthService
            .Setup(x => x.LoginAsync(loginRequest))
            .ReturnsAsync(expectedResponse);

        // Act
        var result = await _authController.Login(loginRequest);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(expectedResponse);
    }

    [Fact]
    public async Task Login_WithInvalidModelState_ShouldReturnValidationProblem()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateInvalidLoginRequest();
        _authController.ModelState.AddModelError("Email", "Email is required");

        // Act
        var result = await _authController.Login(loginRequest);

        // Assert
        result.Should().BeAssignableTo<IActionResult>();

        // ValidationProblem returns different types depending on framework version
        if (result is ObjectResult objectResult)
        {
            // Check if it has the right value type
            objectResult.Value.Should().BeOfType<ValidationProblemDetails>();
        }
        else
        {
            // Could be BadRequestObjectResult
            result.Should().BeOfType<BadRequestObjectResult>();
        }
    }

    [Fact]
    public async Task Login_WhenAuthServiceThrowsUnauthorizedAccessException_ShouldReturnUnauthorizedProblem()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exceptionMessage = "Invalid credentials.";

        _mockAuthService
            .Setup(x => x.LoginAsync(loginRequest))
            .ThrowsAsync(new UnauthorizedAccessException(exceptionMessage));

        // Act
        var result = await _authController.Login(loginRequest);

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
    public async Task Login_WhenAuthServiceThrowsUnauthorizedAccessException_ShouldLogWarning()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exceptionMessage = "Invalid credentials.";

        _mockAuthService
            .Setup(x => x.LoginAsync(loginRequest))
            .ThrowsAsync(new UnauthorizedAccessException(exceptionMessage));

        // Act
        await _authController.Login(loginRequest);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Login failed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task Login_WhenAuthServiceThrowsGeneralException_ShouldReturnInternalServerErrorProblem()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exception = new InvalidOperationException("Database connection failed");

        _mockAuthService
            .Setup(x => x.LoginAsync(loginRequest))
            .ThrowsAsync(exception);

        // Act
        var result = await _authController.Login(loginRequest);

        // Assert
        result.Should().BeOfType<ObjectResult>();
        var objectResult = result as ObjectResult;
        objectResult!.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        var problemDetails = objectResult.Value as ProblemDetails;
        problemDetails.Should().NotBeNull();
        problemDetails!.Title.Should().Be("Internal Server Error");
        problemDetails.Detail.Should().Be("An unexpected error occurred");
    }

    [Fact]
    public async Task Login_WhenAuthServiceThrowsGeneralException_ShouldLogError()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var exception = new InvalidOperationException("Database connection failed");

        _mockAuthService
            .Setup(x => x.LoginAsync(loginRequest))
            .ThrowsAsync(exception);

        // Act
        await _authController.Login(loginRequest);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Unexpected error during login")),
                exception,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task Login_ShouldPassCorrectRequestToAuthService()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedResponse = new LoginResponse
        {
            AccessToken = "test-access-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
        };

        _mockAuthService
            .Setup(x => x.LoginAsync(It.IsAny<LoginRequest>()))
            .ReturnsAsync(expectedResponse);

        // Act
        await _authController.Login(loginRequest);

        // Assert
        _mockAuthService.Verify(
            x => x.LoginAsync(It.Is<LoginRequest>(r =>
                r.Email == loginRequest.Email &&
                r.Password == loginRequest.Password)),
            Times.Once);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task Login_WithInvalidEmail_ShouldReturnBadRequest_AndNotCallAuthService(string invalidEmail)
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Email = invalidEmail!,
            Password = "TestPassword123!",
        };

        // Simulate model validation failure on Email
        if (invalidEmail is null)
        {
            _authController.ModelState.AddModelError(nameof(LoginRequest.Email), "Email is required.");
        }
        else
        {
            _authController.ModelState.AddModelError(nameof(LoginRequest.Email), "Email is invalid.");
        }

        // Act
        var result = await _authController.Login(loginRequest);

        // Assert
        _mockAuthService.Verify(x => x.LoginAsync(It.IsAny<LoginRequest>()), Times.Never);

        result.Should().BeAssignableTo<IActionResult>();

        // ValidationProblem returns different types depending on framework version
        if (result is ObjectResult objectResult)
        {
            objectResult.Value.Should().BeOfType<ValidationProblemDetails>();
        }
        else
        {
            result.Should().BeOfType<BadRequestObjectResult>();
        }
    }

    [Fact]
    public async Task Login_WithNullRequest_ShouldHandleGracefully()
    {
        // Arrange
        LoginRequest? nullRequest = null;

        // Act & Assert
        // This should be handled by model binding and validation
        var act = async () => await _authController.Login(nullRequest!);

        // The framework should handle null requests before reaching the controller action
        // This test ensures our controller doesn't crash if somehow a null gets through
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void Login_ShouldHaveCorrectHttpPostAttribute()
    {
        // Arrange & Act
        var method = typeof(AuthController).GetMethod(nameof(AuthController.Login));

        // Assert
        method.Should().NotBeNull();
        var httpPostAttribute = method!.GetCustomAttributes(typeof(HttpPostAttribute), false).FirstOrDefault();
        httpPostAttribute.Should().NotBeNull();

        var httpPost = httpPostAttribute as HttpPostAttribute;
        httpPost!.Template.Should().Be("login");
    }

    [Fact]
    public void Login_ShouldHaveCorrectProducesResponseTypeAttributes()
    {
        // Arrange & Act
        var method = typeof(AuthController).GetMethod(nameof(AuthController.Login));

        // Assert
        method.Should().NotBeNull();
        var producesResponseTypes = method!.GetCustomAttributes(typeof(ProducesResponseTypeAttribute), false);

        producesResponseTypes.Should().HaveCount(4);

        var responseTypes = producesResponseTypes.Cast<ProducesResponseTypeAttribute>().ToList();

        // Check for 200 OK
        responseTypes.Should().Contain(attr =>
            attr.StatusCode == StatusCodes.Status200OK &&
            attr.Type == typeof(LoginResponse));

        // Check for 400 Bad Request
        responseTypes.Should().Contain(attr =>
            attr.StatusCode == StatusCodes.Status400BadRequest &&
            attr.Type == typeof(ValidationProblemDetails));

        // Check for 401 Unauthorized
        responseTypes.Should().Contain(attr =>
            attr.StatusCode == StatusCodes.Status401Unauthorized &&
            attr.Type == typeof(ProblemDetails));

        // Check for 500 Internal Server Error
        responseTypes.Should().Contain(attr =>
            attr.StatusCode == StatusCodes.Status500InternalServerError &&
            attr.Type == typeof(ProblemDetails));
    }

    [Fact]
    public async Task Login_ShouldReturnCorrectStatusCodeForEachScenario()
    {
        // Test successful login
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var successResponse = new LoginResponse
        {
            AccessToken = "test-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
        };

        _mockAuthService.Setup(x => x.LoginAsync(It.IsAny<LoginRequest>())).ReturnsAsync(successResponse);
        var successResult = await _authController.Login(loginRequest);
        successResult.Should().BeOfType<OkObjectResult>();

        // Test unauthorized scenario
        _mockAuthService.Setup(x => x.LoginAsync(It.IsAny<LoginRequest>()))
            .ThrowsAsync(new UnauthorizedAccessException("Invalid credentials"));
        var unauthorizedResult = await _authController.Login(loginRequest);
        var unauthorizedObjectResult = unauthorizedResult as ObjectResult;
        unauthorizedObjectResult!.StatusCode.Should().Be(401);

        // Test internal server error scenario
        _mockAuthService.Setup(x => x.LoginAsync(It.IsAny<LoginRequest>()))
            .ThrowsAsync(new Exception("Internal error"));
        var errorResult = await _authController.Login(loginRequest);
        var errorObjectResult = errorResult as ObjectResult;
        errorObjectResult!.StatusCode.Should().Be(500);
    }
}
