// <copyright file="TokenServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using FluentAssertions;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

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

    public TokenServiceTests()
    {
        // Arrange - Common setup for all tests
        _mockUserManager = MockHelper.CreateMockUserManager();
        _mockJwtOptions = MockHelper.CreateMockJwtOptions();
        _mockKeyProvider = MockHelper.CreateMockJwtKeyProvider();
        _mockUnitOfWork = new Mock<IUnitOfWork>();
        _mockLogger = MockHelper.CreateMockLogger<TokenService>();
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
}
