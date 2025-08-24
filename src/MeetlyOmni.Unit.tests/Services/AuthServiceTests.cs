// <copyright file="AuthServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

using Moq;

namespace MeetlyOmni.Unit.tests.Services;

/// <summary>
/// Unit tests for AuthService following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class AuthServiceTests
{
    private readonly Mock<UserManager<Member>> _mockUserManager;
    private readonly Mock<SignInManager<Member>> _mockSignInManager;
    private readonly Mock<IJwtTokenService> _mockJwtTokenService;
    private readonly Mock<ILogger<AuthService>> _mockLogger;
    private readonly AuthService _authService;

    public AuthServiceTests()
    {
        // Arrange - Common setup for all tests
        _mockUserManager = MockHelper.CreateMockUserManager();
        _mockSignInManager = MockHelper.CreateMockSignInManager(_mockUserManager.Object);
        _mockJwtTokenService = new Mock<IJwtTokenService>();
        _mockLogger = MockHelper.CreateMockLogger<AuthService>();

        _authService = new AuthService(
            _mockSignInManager.Object,
            _mockUserManager.Object,
            _mockJwtTokenService.Object,
            _mockLogger.Object);
    }

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ShouldReturnLoginResponse()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        var result = await _authService.LoginAsync(loginRequest);

        // Assert
        result.Should().NotBeNull();
        result.AccessToken.Should().Be(expectedTokenResult.accessToken);
        result.ExpiresAt.Should().Be(expectedTokenResult.expiresAt);
        result.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task LoginAsync_WithNonExistentUser_ShouldThrowUnauthorizedAccessException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateNonExistentUserRequest();

        MockHelper.SetupFailedUserLookup(_mockUserManager);

        // Act
        var act = async () => await _authService.LoginAsync(loginRequest);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("Invalid credentials.");
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_ShouldThrowUnauthorizedAccessException()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = TestDataHelper.CreateWrongPasswordRequest();

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupFailedSignIn(_mockSignInManager);

        // Act
        var act = async () => await _authService.LoginAsync(loginRequest);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("Invalid credentials.");
    }

    [Fact]
    public async Task LoginAsync_WithUnconfirmedEmail_ShouldThrowUnauthorizedAccessException()
    {
        // Arrange
        var unconfirmedMember = TestDataHelper.CreateUnconfirmedMember();
        var loginRequest = TestDataHelper.CreateValidLoginRequest();

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, unconfirmedMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        // Act
        var act = async () => await _authService.LoginAsync(loginRequest);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("Email not confirmed.");
    }

    [Fact]
    public async Task LoginAsync_ShouldNormalizeEmailToLowercase()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = new LoginRequest
        {
            Email = "TestUser@EXAMPLE.COM", // Mixed case email
            Password = "TestPassword123!",
        };

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));
        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        await _authService.LoginAsync(loginRequest);

        // Assert
        _mockUserManager.Verify(
            x => x.FindByEmailAsync("testuser@example.com"), // Should be normalized to lowercase
            Times.Once);
    }

    [Fact]
    public async Task LoginAsync_ShouldUpdateLastLoginTime()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var originalLastLogin = testMember.LastLogin;

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));
        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        await _authService.LoginAsync(loginRequest);

        // Assert
        testMember.LastLogin.Should().BeAfter(originalLastLogin!.Value);
        testMember.UpdatedAt.Should().BeAfter(originalLastLogin!.Value);

        _mockUserManager.Verify(
            x => x.UpdateAsync(testMember),
            Times.Once);
    }

    [Fact]
    public async Task LoginAsync_WhenUpdateFails_ShouldStillReturnSuccessButLogWarning()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = TestDataHelper.CreateValidLoginRequest();

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockUserManager
            .Setup(x => x.UpdateAsync(testMember))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "UpdateError", Description = "Update failed" }));

        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));
        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        var result = await _authService.LoginAsync(loginRequest);

        // Assert
        result.Should().NotBeNull();
        result.AccessToken.Should().Be(expectedTokenResult.accessToken);

        // Verify warning was logged
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to update last login")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LoginAsync_ShouldLogSuccessfulLogin()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = TestDataHelper.CreateValidLoginRequest();

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));
        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        await _authService.LoginAsync(loginRequest);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("logged in successfully")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LoginAsync_WhenLoginFails_ShouldLogWarning()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateNonExistentUserRequest();

        MockHelper.SetupFailedUserLookup(_mockUserManager);

        // Act
        var act = async () => await _authService.LoginAsync(loginRequest);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAccessException>();

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Login attempt failed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData("  test@example.com  ", "test@example.com")] // Trim spaces
    [InlineData("TEST@EXAMPLE.COM", "test@example.com")]     // Lowercase
    [InlineData("Test@Example.Com", "test@example.com")]     // Mixed case
    public async Task LoginAsync_ShouldNormalizeEmailCorrectly(string inputEmail, string expectedEmail)
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var loginRequest = new LoginRequest
        {
            Email = inputEmail,
            Password = "TestPassword123!",
        };

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        var expectedTokenResult = new TokenResult("test-token", DateTimeOffset.UtcNow.AddMinutes(15));
        _mockJwtTokenService
            .Setup(x => x.GenerateTokenAsync(testMember))
            .ReturnsAsync(expectedTokenResult);

        // Act
        await _authService.LoginAsync(loginRequest);

        // Assert
        _mockUserManager.Verify(
            x => x.FindByEmailAsync(expectedEmail),
            Times.Once);
    }
}
