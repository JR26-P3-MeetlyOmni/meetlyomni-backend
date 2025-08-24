// <copyright file="AuthService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Service.AuthService;

public class AuthService : IAuthService
{
    private readonly SignInManager<Member> _signInManager;
    private readonly UserManager<Member> _userManager;
    private readonly IJwtTokenService _tokenService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        SignInManager<Member> signInManager,
        UserManager<Member> userManager,
        IJwtTokenService tokenService,
        ILogger<AuthService> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task<LoginResponse> LoginAsync(LoginRequest input)
    {
        var user = await _userManager.FindByEmailAsync(input.Email.Trim()) ?? throw new UnauthorizedAccessException("Invalid email or password.");
        var result = await _signInManager.CheckPasswordSignInAsync(user, input.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            throw new UnauthorizedAccessException("Invalid email or password.");
        }

        // update last login time
        user.LastLogin = DateTimeOffset.UtcNow;
        await _userManager.UpdateAsync(user);
        user.UpdatedAt = DateTimeOffset.UtcNow;
        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            // Non-blocking for login; at least log the errors
            _logger.LogWarning("Failed to update last login for {UserId}: {Errors}", user.Id, string.Join("; ", updateResult.Errors.Select(e => $"{e.Code}:{e.Description}")));
        }

        var token = await _tokenService.GenerateTokenAsync(user);

        return new LoginResponse
        {
            AccessToken = token.accessToken,
            ExpiresAt = token.expiresAt,
            TokenType = "Bearer",
        };
    }
}
