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
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string> { "User", "Admin" });

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        result.Should().NotBeNullOrEmpty();

        // Verify token structure
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        // Check standard JWT claims
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == testMember.Id.ToString());
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == testMember.Email);
        jsonToken.Claims.Should().Contain(c => c.Type == "name" && c.Value == testMember.UserName);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Iat);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldIncludeUserName()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.UserName = "testuser123";

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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().Contain(c => c.Type == "name" && c.Value == testMember.UserName);
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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        var roleClaims = jsonToken.Claims.Where(c => c.Type == "role").ToList();
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
        var result1 = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);
        var result2 = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken1 = tokenHandler.ReadJwtToken(result1);
        var jsonToken2 = tokenHandler.ReadJwtToken(result2);

        var jti1 = jsonToken1.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
        var jti2 = jsonToken2.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;

        jti1.Should().NotBe(jti2);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithCustomUserClaims_ShouldIncludeCustomClaims()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var customClaims = new List<Claim>
        {
            new("department", "Engineering"),
            new("location", "Seattle"),
            new("employee_id", "EMP123")
        };

        var tokenService = new TokenService(
            _mockUserManager.Object,
            _mockUnitOfWork.Object,
            _mockJwtOptions.Object,
            _mockKeyProvider.Object,
            _mockLogger.Object);

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(customClaims);

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().Contain(c => c.Type == "department" && c.Value == "Engineering");
        jsonToken.Claims.Should().Contain(c => c.Type == "location" && c.Value == "Seattle");
        jsonToken.Claims.Should().Contain(c => c.Type == "employee_id" && c.Value == "EMP123");
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithEmptyOrgId_ShouldNotIncludeOrgIdClaim()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.OrgId = Guid.Empty; // Set empty org id

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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().NotContain(c => c.Type == "org_id");
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithNullUserName_ShouldIncludeEmptyNameClaim()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.UserName = null;

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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().Contain(c => c.Type == "name" && c.Value == string.Empty);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithNullEmail_ShouldIncludeEmptyEmailClaim()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.Email = null;

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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == string.Empty);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldSetCorrectTokenExpiration()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var expectedExpirationMinutes = 15; // From mock JWT options

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

        var beforeGeneration = DateTimeOffset.UtcNow;

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var afterGeneration = DateTimeOffset.UtcNow;
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        // Allow some tolerance for test execution time (1 minute buffer)
        var expectedMinExpiry = beforeGeneration.AddMinutes(expectedExpirationMinutes - 1);
        var expectedMaxExpiry = afterGeneration.AddMinutes(expectedExpirationMinutes + 1);

        jsonToken.ValidTo.Should().BeAfter(expectedMinExpiry.UtcDateTime);
        jsonToken.ValidTo.Should().BeBefore(expectedMaxExpiry.UtcDateTime);
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_WithNoRoles_ShouldNotIncludeRoleClaims()
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
            .ReturnsAsync(new List<string>()); // Empty roles

        // Act
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Claims.Should().NotContain(c => c.Type == "role");
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ShouldSetCorrectIssuerAndAudience()
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
        var result = await tokenService.GenerateAccessTokenAsync(testMember, CancellationToken.None);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result);

        jsonToken.Issuer.Should().Be("TestIssuer"); // From mock
        jsonToken.Audiences.Should().Contain("TestAudience"); // From mock
    }

    [Theory]
    [InlineData("test-input")] // Will compute actual hash dynamically
    [InlineData("")] // Empty string
    [InlineData("Hello World")]
    public void ComputeHash_WithKnownInputs_ShouldReturnConsistentHash(string input)
    {
        // Act - Using reflection to test private static method twice to ensure consistency
        var method = typeof(TokenService).GetMethod("ComputeHash",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result1 = method?.Invoke(null, new object[] { input }) as string;
        var result2 = method?.Invoke(null, new object[] { input }) as string;

        // Assert - Should be consistent hash and valid hex string
        result1.Should().NotBeNullOrEmpty();
        result1.Should().Be(result2); // Consistent hashing
        result1.Should().HaveLength(64); // SHA256 produces 64 character hex string
        result1.Should().MatchRegex(@"^[a-f0-9]+$"); // Valid lowercase hex
    }

    [Fact]
    public void GenerateRandomToken_ShouldReturnBase64String()
    {
        // Act - Using reflection to test private static method
        var method = typeof(TokenService).GetMethod("GenerateRandomToken",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = method?.Invoke(null, null) as string;

        // Assert
        result.Should().NotBeNullOrEmpty();
        result.Should().MatchRegex(@"^[A-Za-z0-9+/]+={0,2}$"); // Valid base64 pattern

        // Should be 32 bytes encoded in base64 (32 * 4/3 = ~43 chars with padding)
        result!.Length.Should().Be(44);
    }

    [Fact]
    public void GenerateRandomToken_ShouldReturnUniqueValues()
    {
        // Act - Using reflection to test private static method
        var method = typeof(TokenService).GetMethod("GenerateRandomToken",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        var result1 = method?.Invoke(null, null) as string;
        var result2 = method?.Invoke(null, null) as string;

        // Assert
        result1.Should().NotBe(result2);
    }
}
