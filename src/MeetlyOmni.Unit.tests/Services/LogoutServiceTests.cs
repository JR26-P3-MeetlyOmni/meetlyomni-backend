// <copyright file="LogoutServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;

using FluentAssertions;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Moq;

using Xunit;

namespace MeetlyOmni.Unit.tests.Services;

/// <summary>
/// Unit tests for LogoutService following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class LogoutServiceTests
{
    private readonly Mock<IUnitOfWork> _mockUnitOfWork;
    private readonly Mock<ILogger<LogoutService>> _mockLogger;

    public LogoutServiceTests()
    {
        _mockUnitOfWork = new Mock<IUnitOfWork>();
        _mockLogger = MockHelper.CreateMockLogger<LogoutService>();
    }

    [Fact]
    public async Task LogoutAsync_WithValidRefreshToken_ShouldRevokeTokensAndClearCookies()
    {
        // Arrange
        var refreshToken = "valid-refresh-token";
        var tokenHash = ComputeHash(refreshToken);
        var familyId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        var storedToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            FamilyId = familyId,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            FamilyExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            CreatedAt = DateTimeOffset.UtcNow,
            UserAgent = "TestUserAgent",
            IpAddress = "127.0.0.1",
            RevokedAt = null,
            ReplacedByHash = null
        };

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        var logoutService = new LogoutService(
            _mockUnitOfWork.Object,
            _mockLogger.Object);

        _mockUnitOfWork
            .Setup(x => x.RefreshTokens.FindByHashAsync(tokenHash, It.IsAny<CancellationToken>()))
            .ReturnsAsync(storedToken);

        _mockUnitOfWork
            .Setup(x => x.RefreshTokens.MarkTokenFamilyAsRevokedAsync(familyId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3); // Mock that 3 tokens were revoked

        _mockUnitOfWork
            .Setup(x => x.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        // Act
        await logoutService.LogoutAsync(httpContext, CancellationToken.None);

        // Assert
        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.FindByHashAsync(tokenHash, It.IsAny<CancellationToken>()),
            Times.Once);

        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.MarkTokenFamilyAsRevokedAsync(familyId, It.IsAny<CancellationToken>()),
            Times.Once);

        _mockUnitOfWork.Verify(
            x => x.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Once);

        // Verify that cookies are cleared (they should be set to expire in the past)
        var accessTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        var refreshTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.RefreshToken));

        accessTokenCookie.Should().NotBeNull();
        refreshTokenCookie.Should().NotBeNull();
        accessTokenCookie.Should().Contain("expires=");
        refreshTokenCookie.Should().Contain("expires=");
    }

    [Fact]
    public async Task LogoutAsync_WithNoRefreshToken_ShouldNotRevokeTokensButClearCookies()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        // No refresh token in cookies

        var logoutService = new LogoutService(
            _mockUnitOfWork.Object,
            _mockLogger.Object);

        // Act
        await logoutService.LogoutAsync(httpContext, CancellationToken.None);

        // Assert
        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.FindByHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);

        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.MarkTokenFamilyAsRevokedAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
            Times.Never);

        _mockUnitOfWork.Verify(
            x => x.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);

        // Verify that cookies are still cleared
        var accessTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        var refreshTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.RefreshToken));

        accessTokenCookie.Should().NotBeNull();
        refreshTokenCookie.Should().NotBeNull();
    }

    [Fact]
    public async Task LogoutAsync_WithInvalidRefreshToken_ShouldNotRevokeTokensButClearCookies()
    {
        // Arrange
        var refreshToken = "invalid-refresh-token";
        var tokenHash = ComputeHash(refreshToken);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}={refreshToken}";

        var logoutService = new LogoutService(
            _mockUnitOfWork.Object,
            _mockLogger.Object);

        _mockUnitOfWork
            .Setup(x => x.RefreshTokens.FindByHashAsync(tokenHash, It.IsAny<CancellationToken>()))
            .ReturnsAsync((RefreshToken?)null);

        // Act
        await logoutService.LogoutAsync(httpContext, CancellationToken.None);

        // Assert
        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.FindByHashAsync(tokenHash, It.IsAny<CancellationToken>()),
            Times.Once);

        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.MarkTokenFamilyAsRevokedAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
            Times.Never);

        _mockUnitOfWork.Verify(
            x => x.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);

        // Verify that cookies are still cleared
        var accessTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        var refreshTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.RefreshToken));

        accessTokenCookie.Should().NotBeNull();
        refreshTokenCookie.Should().NotBeNull();
    }

    [Fact]
    public async Task LogoutAsync_WithEmptyRefreshToken_ShouldNotRevokeTokensButClearCookies()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Cookie = $"{AuthCookieExtensions.CookieNames.RefreshToken}=";

        var logoutService = new LogoutService(
            _mockUnitOfWork.Object,
            _mockLogger.Object);

        // Act
        await logoutService.LogoutAsync(httpContext, CancellationToken.None);

        // Assert
        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.FindByHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);

        _mockUnitOfWork.Verify(
            x => x.RefreshTokens.MarkTokenFamilyAsRevokedAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
            Times.Never);

        _mockUnitOfWork.Verify(
            x => x.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);

        // Verify that cookies are still cleared
        var accessTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.AccessToken));
        var refreshTokenCookie = httpContext.Response.Headers["Set-Cookie"]
            .FirstOrDefault(c => c.Contains(AuthCookieExtensions.CookieNames.RefreshToken));

        accessTokenCookie.Should().NotBeNull();
        refreshTokenCookie.Should().NotBeNull();
    }

    private static string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashedBytes).ToLowerInvariant();
    }
}
