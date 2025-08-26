// <copyright file="TokenServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using FluentAssertions;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

namespace MeetlyOmni.Unit.tests.Services;

/// <summary>
/// Unit tests for TokenService following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class TokenServiceTests
{
    private readonly Mock<UserManager<Member>> _mockUserManager;
    private readonly Mock<IOptions<JwtOptions>> _mockJwtOptions;
    private readonly Mock<IJwtKeyProvider> _mockKeyProvider;
    private readonly Mock<IUnitOfWork> _mockUnitOfWork;
    private readonly Mock<ILogger<TokenService>> _mockLogger;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;

    public TokenServiceTests()
    {
        // Arrange - Common setup for all tests
        _mockUserManager = MockHelper.CreateMockUserManager();
        _mockJwtOptions = MockHelper.CreateMockJwtOptions();
        _mockKeyProvider = MockHelper.CreateMockJwtKeyProvider();
        _mockUnitOfWork = new Mock<IUnitOfWork>();
        _mockLogger = MockHelper.CreateMockLogger<TokenService>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();

        _mockUnitOfWork.Setup(u => u.RefreshTokens).Returns(_mockRefreshTokenRepository.Object);
    }


    // Note: GenerateTokenPairAsync requires database operations and is better tested in integration tests

    [Fact]
    public async Task GenerateAccessTokenAsync_WithValidMember_ShouldReturnValidToken()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();



        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>
            {
                new("full_name", "Test User"),
            });

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string> { "User", "Admin" });

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember);

        // Assert
        result.Should().NotBeNullOrEmpty();

        // Verify token structure
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        // Check standard JWT claims
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == testMember.Id.ToString());
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == testMember.Email);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Iat);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldIncludeOrganizationId()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();


        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().Contain(c => c.Type == "org_id" && c.Value == testMember.OrgId.ToString());
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldIncludeUserRoles()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var expectedRoles = new List<string> { "User", "Admin", "Manager" };


        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(expectedRoles);

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        var roleClaims = jsonToken.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
        roleClaims.Should().HaveCount(expectedRoles.Count);

        foreach (var expectedRole in expectedRoles)
        {
            roleClaims.Should().Contain(c => c.Value == expectedRole);
        }
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldGenerateUniqueJti()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();


        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result1 = await tokenService.GenerateAccessTokenAsync(testMember);
        var result2 = await tokenService.GenerateAccessTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken1 = tokenHandler.ReadJwtToken(result1);
        var jsonToken2 = tokenHandler.ReadJwtToken(result2);

        var jti1 = jsonToken1.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
        var jti2 = jsonToken2.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;

        jti1.Should().NotBe(jti2);
    }

    // ---------------------------
    // LogoutAsync Tests
    // ---------------------------

    [Fact]
    public async Task LogoutAsync_WithValidRefreshToken_ShouldMarkTokenAsRevokedAndSaveChanges()
    {
        // Arrange
        var refreshTokenValue = "valid-refresh-token";
        var tokenHash = TokenServiceTestsHelper.ComputeHash(refreshTokenValue);
        var storedToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = tokenHash,
            UserId = Guid.NewGuid(),
            RevokedAt = null // Not yet revoked
        };

        _mockRefreshTokenRepository
            .Setup(r => r.FindByHashAsync(tokenHash))
            .ReturnsAsync(storedToken);

        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        // Act
        var result = await tokenService.LogoutAsync(refreshTokenValue);

        // Assert
        result.Should().BeTrue();
        storedToken.RevokedAt.Should().NotBeNull();
        storedToken.RevokedAt.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));

        _mockRefreshTokenRepository.Verify(r => r.Update(storedToken), Times.Once);
        _mockUnitOfWork.Verify(u => u.SaveChangesAsync(), Times.Once);
    }

    [Fact]
    public async Task LogoutAsync_WithInvalidRefreshToken_ShouldReturnFalse()
    {
        // Arrange
        var refreshTokenValue = "invalid-refresh-token";
        var tokenHash = TokenServiceTestsHelper.ComputeHash(refreshTokenValue);

        _mockRefreshTokenRepository
            .Setup(r => r.FindByHashAsync(tokenHash))
            .ReturnsAsync((RefreshToken?)null);

        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        // Act
        var result = await tokenService.LogoutAsync(refreshTokenValue);

        // Assert
        result.Should().BeFalse();
        _mockRefreshTokenRepository.Verify(r => r.Update(It.IsAny<RefreshToken>()), Times.Never);
        _mockUnitOfWork.Verify(u => u.SaveChangesAsync(), Times.Never);
    }

    [Fact]
    public async Task LogoutAsync_WithAlreadyRevokedToken_ShouldReturnTrueWithoutUpdating()
    {
        // Arrange
        var refreshTokenValue = "already-revoked-token";
        var tokenHash = TokenServiceTestsHelper.ComputeHash(refreshTokenValue);
        var alreadyRevokedTime = DateTimeOffset.UtcNow.AddHours(-1);
        var storedToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = tokenHash,
            UserId = Guid.NewGuid(),
            RevokedAt = alreadyRevokedTime // Already revoked
        };

        _mockRefreshTokenRepository
            .Setup(r => r.FindByHashAsync(tokenHash))
            .ReturnsAsync(storedToken);

        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        // Act
        var result = await tokenService.LogoutAsync(refreshTokenValue);

        // Assert
        result.Should().BeTrue();
        storedToken.RevokedAt.Should().Be(alreadyRevokedTime); // Should not change

        _mockRefreshTokenRepository.Verify(r => r.Update(It.IsAny<RefreshToken>()), Times.Never);
        _mockUnitOfWork.Verify(u => u.SaveChangesAsync(), Times.Never);
    }

    [Fact]
    public async Task LogoutAsync_WhenRepositoryThrows_ShouldPropagateException()
    {
        // Arrange
        var refreshTokenValue = "refresh-token-error";
        var tokenHash = TokenServiceTestsHelper.ComputeHash(refreshTokenValue);

        _mockRefreshTokenRepository
            .Setup(r => r.FindByHashAsync(tokenHash))
            .ThrowsAsync(new Exception("Database failure"));

        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        // Act
        var act = async () => await tokenService.LogoutAsync(refreshTokenValue);

        // Assert
        await act.Should().ThrowAsync<Exception>().WithMessage("Database failure");
    }

    // Helper class for test utilities
    public static class TokenServiceTestsHelper
    {
        public static string ComputeHash(string input)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hashedBytes).ToLowerInvariant();
        }
    }

}
