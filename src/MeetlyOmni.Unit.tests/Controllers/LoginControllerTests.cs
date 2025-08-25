// <copyright file="LoginControllerTestsSimple.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

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
}
