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
        // standardize email to avoid case-sensitive issues
        var email = input.Email.Trim().ToLowerInvariant();

        // prevent user enumeration attack: even if user does not exist, password validation is performed
        var user = await _userManager.FindByEmailAsync(email);

        // always perform password check, prevent timing attacks
        var result = user != null
            ? await _signInManager.CheckPasswordSignInAsync(user, input.Password, lockoutOnFailure: true)
            : SignInResult.Failed;

        if (!result.Succeeded || user == null)
        {
            // log login failure but do not expose specific reason
            _logger.LogWarning("Login attempt failed for email: {Email}", email);

            // unified error message, do not leak whether user exists
            throw new UnauthorizedAccessException("Invalid credentials.");
        }

        // check user status
        if (!user.EmailConfirmed)
        {
            _logger.LogWarning("Login attempt with unconfirmed email: {Email}", email);
            throw new UnauthorizedAccessException("Email not confirmed.");
        }

        // update user info in one go, avoid multiple database calls
        user.LastLogin = DateTimeOffset.UtcNow;
        user.UpdatedAt = DateTimeOffset.UtcNow;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            // Non-blocking for login; at least log the errors
            _logger.LogWarning(
                "Failed to update last login for {UserId}: {Errors}",
                user.Id,
                string.Join("; ", updateResult.Errors.Select(e => $"{e.Code}:{e.Description}")));
        }

        var token = await _tokenService.GenerateTokenAsync(user);

        _logger.LogInformation("User {UserId} logged in successfully", user.Id);

        return new LoginResponse
        {
            AccessToken = token.accessToken,
            ExpiresAt = token.expiresAt,
            TokenType = "Bearer",
        };
    }
}
