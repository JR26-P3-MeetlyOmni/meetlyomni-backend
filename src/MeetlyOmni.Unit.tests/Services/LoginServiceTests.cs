// <copyright file="LoginServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using FluentAssertions;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Filters;
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
            DateTimeOffset.UtcNow.AddDays(30)
        );

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockTokenService
            .Setup(x => x.GenerateTokenPairAsync(testMember, userAgent, ipAddress, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenResult);

        // Act
        var result = await _loginService.LoginAsync(loginRequest, userAgent, ipAddress, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.ExpiresAt.Should().Be(tokenResult.accessTokenExpiresAt);
        result.TokenType.Should().Be("Bearer");
        result.AccessToken.Should().Be(tokenResult.accessToken);
        result.RefreshToken.Should().Be(tokenResult.refreshToken);
    }

    [Fact]
    public async Task LoginAsync_WithNonExistentUser_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        loginRequest.Email = "nonexistent@example.com";

        _mockUserManager
            .Setup(x => x.FindByEmailAsync(loginRequest.Email))
            .ReturnsAsync((Member?)null);

        // Act
        var act = () => _loginService.LoginAsync(loginRequest, "test-agent", "127.0.0.1", CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAppException>()
            .WithMessage("Invalid credentials.");
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_ShouldThrowUnauthorizedAppException()
    {
        // Arrange
        var loginRequest = TestDataHelper.CreateValidLoginRequest();
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.FindByEmailAsync(loginRequest.Email))
            .ReturnsAsync(testMember);

        _mockSignInManager
            .Setup(x => x.CheckPasswordSignInAsync(testMember, loginRequest.Password, true))
            .ReturnsAsync(SignInResult.Failed);

        // Act
        var act = () => _loginService.LoginAsync(loginRequest, "test-agent", "127.0.0.1", CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAppException>()
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
            DateTimeOffset.UtcNow.AddDays(30)
        );

        MockHelper.SetupSuccessfulUserLookup(_mockUserManager, testMember);
        MockHelper.SetupSuccessfulSignIn(_mockSignInManager);

        _mockTokenService
            .Setup(x => x.GenerateTokenPairAsync(It.IsAny<Member>(), It.IsAny<string>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenResult);

        // Act
        await _loginService.LoginAsync(loginRequest, userAgent, ipAddress, CancellationToken.None);

        // Assert
        _mockTokenService.Verify(
            x => x.GenerateTokenPairAsync(testMember, userAgent, ipAddress, null, It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
