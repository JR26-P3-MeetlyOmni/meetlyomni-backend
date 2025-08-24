// <copyright file="JwtTokenServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using FluentAssertions;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

namespace MeetlyOmni.Unit.tests.Services;

/// <summary>
/// Unit tests for JwtTokenService following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class JwtTokenServiceTests
{
    private readonly Mock<UserManager<Member>> _mockUserManager;
    private readonly Mock<IOptions<JwtOptions>> _mockJwtOptions;
    private readonly Mock<IJwtKeyProvider> _mockKeyProvider;
    private readonly JwtTokenService _jwtTokenService;

    public JwtTokenServiceTests()
    {
        // Arrange - Common setup for all tests
        _mockUserManager = MockHelper.CreateMockUserManager();
        _mockJwtOptions = MockHelper.CreateMockJwtOptions();
        _mockKeyProvider = MockHelper.CreateMockJwtKeyProvider();

        _jwtTokenService = new JwtTokenService(
            _mockJwtOptions.Object,
            _mockUserManager.Object,
            _mockKeyProvider.Object);
    }

    [Fact]
    public async Task GenerateTokenAsync_WithValidMember_ShouldReturnValidToken()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

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
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        result.Should().NotBeNull();
        result.accessToken.Should().NotBeNullOrEmpty();
        result.expiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
        result.expiresAt.Should().BeBefore(DateTimeOffset.UtcNow.AddMinutes(16)); // Should be around 15 minutes
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldIncludeStandardClaims()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        // Check standard JWT claims
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == testMember.Id.ToString());
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == testMember.Email);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti);
        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Iat);
        // nbf and exp are now automatically handled by JwtSecurityToken constructor
        jsonToken.ValidFrom.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        jsonToken.ValidTo.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(15), TimeSpan.FromSeconds(5));

        // Check that we no longer include redundant custom claims (they were removed in optimization)
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldIncludeOrganizationId()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().Contain(c => c.Type == "org_id" && c.Value == testMember.OrgId.ToString());
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldNotIncludeOrgIdWhenEmpty()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.OrgId = Guid.Empty; // Set to empty GUID

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().NotContain(c => c.Type == "org_id");
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldIncludeUserRoles()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var expectedRoles = new List<string> { "User", "Admin", "Manager" };

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(expectedRoles);

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        var roleClaims = jsonToken.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
        roleClaims.Should().HaveCount(expectedRoles.Count);

        foreach (var expectedRole in expectedRoles)
        {
            roleClaims.Should().Contain(c => c.Value == expectedRole);
        }
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldIncludeFullNameClaim()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        var expectedFullName = "John Doe";

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>
            {
                new("full_name", expectedFullName),
                new("some_other_claim", "other_value"),
            });

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().Contain(c => c.Type == ClaimTypes.GivenName && c.Value == expectedFullName);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldNotIncludeFullNameWhenEmpty()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>
            {
                new("full_name", string.Empty), // Empty full name
                new("other_claim", "value"),
            });

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().NotContain(c => c.Type == ClaimTypes.GivenName);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldNotIncludeFullNameWhenNull()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>
            {
                new("other_claim", "value"),
            });

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().NotContain(c => c.Type == ClaimTypes.GivenName);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldSetCorrectIssuerAndAudience()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Issuer.Should().Be("TestIssuer");
        jsonToken.Audiences.Should().Contain("TestAudience");
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldBatchUserClaimsAndRoles()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        result.Should().NotBeNull();

        // Verify both methods were called exactly once (batched execution)
        _mockUserManager.Verify(x => x.GetClaimsAsync(testMember), Times.Once);
        _mockUserManager.Verify(x => x.GetRolesAsync(testMember), Times.Once);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldHandleNullEmail()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();
        testMember.Email = null; // Null email

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadJwtToken(result.accessToken);

        jsonToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == string.Empty);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldGenerateUniqueJti()
    {
        // Arrange
        var testMember = TestDataHelper.CreateTestMember();

        _mockUserManager
            .Setup(x => x.GetClaimsAsync(testMember))
            .ReturnsAsync(new List<Claim>());

        _mockUserManager
            .Setup(x => x.GetRolesAsync(testMember))
            .ReturnsAsync(new List<string>());

        // Act
        var result1 = await _jwtTokenService.GenerateTokenAsync(testMember);
        var result2 = await _jwtTokenService.GenerateTokenAsync(testMember);

        // Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken1 = tokenHandler.ReadJwtToken(result1.accessToken);
        var jsonToken2 = tokenHandler.ReadJwtToken(result2.accessToken);

        var jti1 = jsonToken1.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
        var jti2 = jsonToken2.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;

        jti1.Should().NotBe(jti2);
    }
}
