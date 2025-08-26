// <copyright file="LoginServiceTests.cs" company="MeetlyOmni">
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

using Xunit;

namespace MeetlyOmni.Unit.tests.Services;

/// <summary>
/// Unit tests for LoginService following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class LoginServiceTests
{
    private readonly Mock<UserManager<Member>> _mockUserManager;
    private readonly Mock<SignInManager<Member>> _mockSignInManager;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<ILogger<LoginService>> _mockLogger;
    private readonly LoginService _loginService;

    public LoginServiceTests()
    {
        // Arrange - Common setup for all tests
        _mockUserManager = MockHelper.CreateMockUserManager();
        _mockSignInManager = MockHelper.CreateMockSignInManager(_mockUserManager.Object);
        _mockTokenService = new Mock<ITokenService>();
        _mockLogger = MockHelper.CreateMockLogger<LoginService>();

        _loginService = new LoginService(
            _mockSignInManager.Object,
            _mockUserManager.Object,
            _mockTokenService.Object,
            _mockLogger.Object);
    }

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ShouldReturnInternalLoginResponse()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var testMember = TestDataHelper.CreateTestMember();
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";

        var tokenResult = new TokenResult(
            "access-token",
            DateTimeOffset.UtcNow.AddMinutes(15),
            "refresh-token",
            DateTimeOffset.UtcNow.AddDays(7)
        );

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockTokenService
            .Setup(x => x.GenerateTokenPairAsync(testMember, userAgent, ipAddress, null))
            .ReturnsAsync(tokenResult);

        // Act
        var result = await _loginService.LoginAsync(loginRequest, userAgent, ipAddress);

        // Assert
        result.Should().NotBeNull();
        result.ExpiresAt.Should().Be(tokenResult.accessTokenExpiresAt);
        result.TokenType.Should().Be("Bearer");
        result.AccessToken.Should().Be(tokenResult.accessToken);
        result.RefreshToken.Should().Be(tokenResult.refreshToken);
    }

    [Fact]
    public async Task LoginAsync_WithNonExistentUser_ShouldThrowUnauthorizedAccessException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateNonExistentUserRequest();
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";

        MockHelper.SetupFailedUserLookup(_mockUserManager);

        // Act & Assert
        var act = async () => await _loginService.LoginAsync(loginRequest, userAgent, ipAddress);
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("Invalid credentials.");
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_ShouldThrowUnauthorizedAccessException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateWrongPasswordRequest();
        var testMember = TestDataHelper.CreateTestMember();
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupFailedSignIn(_mockSignInManager);

        // Act & Assert
        var act = async () => await _loginService.LoginAsync(loginRequest, userAgent, ipAddress);
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("Invalid credentials.");
    }

    [Fact]
    public async Task LoginAsync_ShouldCallTokenServiceWithCorrectParameters()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var testMember = TestDataHelper.CreateTestMember();
        var userAgent = "TestUserAgent";
        var ipAddress = "192.168.1.1";

        var tokenResult = new TokenResult(
            "access-token",
            DateTimeOffset.UtcNow.AddMinutes(15),
            "refresh-token",
            DateTimeOffset.UtcNow.AddDays(7)
        );

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockTokenService
            .Setup(x => x.GenerateTokenPairAsync(It.IsAny<Member>(), It.IsAny<string>(), It.IsAny<string>(), null))
            .ReturnsAsync(tokenResult);

        // Act
        await _loginService.LoginAsync(loginRequest, userAgent, ipAddress);

        // Assert
        _mockTokenService.Verify(
            x => x.GenerateTokenPairAsync(testMember, userAgent, ipAddress, null),
            Times.Once);
    }
}
