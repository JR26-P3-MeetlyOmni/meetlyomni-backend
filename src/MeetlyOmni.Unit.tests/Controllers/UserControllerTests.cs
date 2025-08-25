// <copyright file="UserControllerTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using FluentAssertions;

using MeetlyOmni.Api.Controllers;
using MeetlyOmni.Unit.tests.Helpers;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using Xunit;

namespace MeetlyOmni.Unit.tests.Controllers;

/// <summary>
/// Unit tests for UserController following AAA (Arrange-Act-Assert) principle.
/// </summary>
public class UserControllerTests
{
    private readonly UserController _userController;

    public UserControllerTests()
    {
        // Arrange - Common setup for all tests
        var mockLogger = MockHelper.CreateMockLogger<UserController>();
        _userController = new UserController(mockLogger.Object);

        // Setup HttpContext with default claims
        var httpContext = new DefaultHttpContext();
        _userController.ControllerContext = new ControllerContext()
        {
            HttpContext = httpContext
        };
    }

    [Fact]
    public void GetCurrentUser_WithValidClaims_ShouldReturnOkWithUserInfo()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var email = "test@example.com";
        var orgId = Guid.NewGuid().ToString();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, email),
            new("org_id", orgId)
        };

        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        response.Should().NotBeNull();

        // Use reflection to check the anonymous object properties
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");
        var messageProperty = responseType.GetProperty("message");

        userIdProperty!.GetValue(response).Should().Be(userId);
        emailProperty!.GetValue(response).Should().Be(email);
        orgIdProperty!.GetValue(response).Should().Be(orgId);
        messageProperty!.GetValue(response).Should().Be("Authentication via cookie is working!");
    }

    [Fact]
    public void GetCurrentUser_WithMissingUserIdClaim_ShouldReturnOkWithNullUserId()
    {
        // Arrange
        var email = "test@example.com";
        var orgId = Guid.NewGuid().ToString();

        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, email),
            new("org_id", orgId)
        };

        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");

        userIdProperty!.GetValue(response).Should().BeNull();
        emailProperty!.GetValue(response).Should().Be(email);
        orgIdProperty!.GetValue(response).Should().Be(orgId);
    }

    [Fact]
    public void GetCurrentUser_WithMissingEmailClaim_ShouldReturnOkWithNullEmail()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var orgId = Guid.NewGuid().ToString();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new("org_id", orgId)
        };

        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");

        userIdProperty!.GetValue(response).Should().Be(userId);
        emailProperty!.GetValue(response).Should().BeNull();
        orgIdProperty!.GetValue(response).Should().Be(orgId);
    }

    [Fact]
    public void GetCurrentUser_WithMissingOrgIdClaim_ShouldReturnOkWithNullOrgId()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var email = "test@example.com";

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, email)
        };

        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");

        userIdProperty!.GetValue(response).Should().Be(userId);
        emailProperty!.GetValue(response).Should().Be(email);
        orgIdProperty!.GetValue(response).Should().BeNull();
    }

    [Fact]
    public void GetCurrentUser_WithNoClaims_ShouldReturnOkWithAllNullValues()
    {
        // Arrange
        var identity = new ClaimsIdentity(); // No claims
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");

        userIdProperty!.GetValue(response).Should().BeNull();
        emailProperty!.GetValue(response).Should().BeNull();
        orgIdProperty!.GetValue(response).Should().BeNull();
    }

    [Fact]
    public void GetCurrentUser_WithEmptyStringClaims_ShouldReturnEmptyStrings()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, string.Empty),
            new(ClaimTypes.Email, string.Empty),
            new("org_id", string.Empty)
        };

        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        _userController.HttpContext.User = principal;

        // Act
        var result = _userController.GetCurrentUser();

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        var okResult = result as OkObjectResult;

        var response = okResult!.Value;
        var responseType = response!.GetType();
        var userIdProperty = responseType.GetProperty("userId");
        var emailProperty = responseType.GetProperty("email");
        var orgIdProperty = responseType.GetProperty("orgId");

        userIdProperty!.GetValue(response).Should().Be(string.Empty);
        emailProperty!.GetValue(response).Should().Be(string.Empty);
        orgIdProperty!.GetValue(response).Should().Be(string.Empty);
    }

    [Fact]
    public void GetCurrentUser_ShouldHaveCorrectHttpGetAttribute()
    {
        // Arrange & Act
        var method = typeof(UserController).GetMethod(nameof(UserController.GetCurrentUser));

        // Assert
        method.Should().NotBeNull();
        var httpGetAttribute = method!.GetCustomAttributes(typeof(HttpGetAttribute), false).FirstOrDefault();
        httpGetAttribute.Should().NotBeNull();

        var httpGet = httpGetAttribute as HttpGetAttribute;
        httpGet!.Template.Should().Be("me");
    }

    [Fact]
    public void GetCurrentUser_ShouldHaveCorrectProducesResponseTypeAttribute()
    {
        // Arrange & Act
        var method = typeof(UserController).GetMethod(nameof(UserController.GetCurrentUser));

        // Assert
        method.Should().NotBeNull();
        var producesResponseTypes = method!.GetCustomAttributes(typeof(ProducesResponseTypeAttribute), false);

        producesResponseTypes.Should().HaveCount(2);

        var responseType = producesResponseTypes.Cast<ProducesResponseTypeAttribute>().First();
        responseType.StatusCode.Should().Be(StatusCodes.Status200OK);
    }



    [Fact]
    public void UserController_ShouldHaveCorrectApiControllerAttribute()
    {
        // Arrange & Act
        var controllerType = typeof(UserController);
        var apiControllerAttribute = controllerType.GetCustomAttributes(typeof(ApiControllerAttribute), false).FirstOrDefault();

        // Assert
        apiControllerAttribute.Should().NotBeNull();
    }

    [Fact]
    public void UserController_ShouldHaveCorrectRouteAttribute()
    {
        // Arrange & Act
        var controllerType = typeof(UserController);
        var routeAttribute = controllerType.GetCustomAttributes(typeof(RouteAttribute), false).FirstOrDefault();

        // Assert
        routeAttribute.Should().NotBeNull();
        var route = routeAttribute as RouteAttribute;
        route!.Template.Should().Be("api/[controller]");
    }
}
