// <copyright file="MockHelper.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Moq;

namespace MeetlyOmni.Unit.tests.Helpers;

/// <summary>
/// Helper class for creating mocks.
/// </summary>
public static class MockHelper
{
    /// <summary>
    /// Creates a mock UserManager for Member.
    /// </summary>
    /// <returns>A mock UserManager.</returns>
    public static Mock<UserManager<Member>> CreateMockUserManager()
    {
        var store = new Mock<IUserStore<Member>>();
        var mgr = new Mock<UserManager<Member>>(store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        mgr.Object.UserValidators.Add(new UserValidator<Member>());
        mgr.Object.PasswordValidators.Add(new PasswordValidator<Member>());
        return mgr;
    }

    /// <summary>
    /// Creates a mock SignInManager for Member.
    /// </summary>
    /// <param name="userManager">The UserManager to use.</param>
    /// <returns>A mock SignInManager.</returns>
    public static Mock<SignInManager<Member>> CreateMockSignInManager(UserManager<Member> userManager)
    {
        var contextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var userPrincipalFactory = new Mock<IUserClaimsPrincipalFactory<Member>>();
        var options = new Mock<IOptions<IdentityOptions>>();
        var logger = new Mock<ILogger<SignInManager<Member>>>();

        return new Mock<SignInManager<Member>>(
            userManager,
            contextAccessor.Object,
            userPrincipalFactory.Object,
            options.Object,
            logger.Object,
            null!,
            null!);
    }

    /// <summary>
    /// Creates a mock JWT key provider.
    /// </summary>
    /// <returns>A mock IJwtKeyProvider.</returns>
    public static Mock<IJwtKeyProvider> CreateMockJwtKeyProvider()
    {
        var mock = new Mock<IJwtKeyProvider>();
        var key = new SymmetricSecurityKey(new byte[32]); // 256-bit key

        mock.Setup(x => x.GetSigningKey()).Returns(key);
        mock.Setup(x => x.GetValidationKey()).Returns(key);

        return mock;
    }

    /// <summary>
    /// Creates mock JWT options.
    /// </summary>
    /// <returns>A mock IOptions&lt;JwtOptions&gt;.</returns>
    public static Mock<IOptions<JwtOptions>> CreateMockJwtOptions()
    {
        var jwtOptions = new JwtOptions
        {
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenExpirationMinutes = 15,
        };

        var mock = new Mock<IOptions<JwtOptions>>();
        mock.Setup(x => x.Value).Returns(jwtOptions);

        return mock;
    }

    /// <summary>
    /// Creates a mock logger.
    /// </summary>
    /// <typeparam name="T">The type for the logger.</typeparam>
    /// <returns>A mock ILogger.</returns>
    public static Mock<ILogger<T>> CreateMockLogger<T>()
    {
        return new Mock<ILogger<T>>();
    }

    /// <summary>
    /// Sets up UserManager mock for successful user lookup.
    /// </summary>
    /// <param name="mockUserManager">The mock UserManager.</param>
    /// <param name="member">The member to return.</param>
    public static void SetupSuccessfulUserLookup(Mock<UserManager<Member>> mockUserManager, Member member)
    {
        mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync(member);

        mockUserManager.Setup(x => x.GetClaimsAsync(member))
            .ReturnsAsync(new List<Claim>
            {
                new("full_name", "Test User"),
            });

        mockUserManager.Setup(x => x.GetRolesAsync(member))
            .ReturnsAsync(new List<string> { "User" });

        mockUserManager.Setup(x => x.UpdateAsync(member))
            .ReturnsAsync(IdentityResult.Success);
    }

    /// <summary>
    /// Sets up UserManager mock for failed user lookup.
    /// </summary>
    /// <param name="mockUserManager">The mock UserManager.</param>
    public static void SetupFailedUserLookup(Mock<UserManager<Member>> mockUserManager)
    {
        mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((Member?)null);
    }

    /// <summary>
    /// Sets up SignInManager mock for successful sign in.
    /// </summary>
    /// <param name="mockSignInManager">The mock SignInManager.</param>
    public static void SetupSuccessfulSignIn(Mock<SignInManager<Member>> mockSignInManager)
    {
        mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(It.IsAny<Member>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(SignInResult.Success);
    }

    /// <summary>
    /// Sets up SignInManager mock for failed sign in.
    /// </summary>
    /// <param name="mockSignInManager">The mock SignInManager.</param>
    public static void SetupFailedSignIn(Mock<SignInManager<Member>> mockSignInManager)
    {
        mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(It.IsAny<Member>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(SignInResult.Failed);
    }
}
