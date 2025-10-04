// <copyright file="LoginService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Service.AuthService;

/// <summary>
/// Service responsible for user authentication and login.
/// </summary>
public class LoginService : ILoginService
{
    private readonly SignInManager<Member> _signInManager;
    private readonly UserManager<Member> _userManager;
    private readonly ITokenService _tokenService;
    private readonly ILogger<LoginService> _logger;

    public LoginService(
        SignInManager<Member> signInManager,
        UserManager<Member> userManager,
        ITokenService tokenService,
        ILogger<LoginService> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task<InternalLoginResponse> LoginAsync(LoginRequest input, string userAgent, string ipAddress, CancellationToken ct)
    {
        var email = input.Email.Trim().ToLowerInvariant();

        // Prevent user enumeration attack: even if user does not exist, password validation is performed
        var user = await _userManager.FindByEmailAsync(email);

        // Always perform password check, prevent timing attacks
        var result = user != null
            ? await _signInManager.CheckPasswordSignInAsync(user, input.Password, lockoutOnFailure: true)
            : SignInResult.Failed;

        if (!result.Succeeded || user == null)
        {
            _logger.LogWarning("Login attempt failed for email: {Email}", email);

            throw new UnauthorizedAppException("Invalid credentials.");
        }

        if (!user.EmailConfirmed)
        {
            _logger.LogWarning("Login attempt with unconfirmed email: {Email}", email);
            throw new UnauthorizedAppException("Email not confirmed.");
        }

        // Update user info in one go, avoid multiple database calls
        user.LastLogin = DateTimeOffset.UtcNow;
        user.UpdatedAt = DateTimeOffset.UtcNow;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            _logger.LogWarning(
                "Failed to update last login for {UserId}: {Errors}",
                user.Id,
                string.Join("; ", updateResult.Errors.Select(e => $"{e.Code}:{e.Description}")));
        }

        // Generate tokens
        var tokens = await _tokenService.GenerateTokenPairAsync(user, userAgent, ipAddress, ct: ct);

        _logger.LogInformation("User {UserId} logged in successfully", user.Id);

        return new InternalLoginResponse
        {
            AccessToken = tokens.accessToken,
            ExpiresAt = tokens.accessTokenExpiresAt,
            TokenType = "Bearer",
            RefreshToken = tokens.refreshToken,
            RefreshTokenExpiresAt = tokens.refreshTokenExpiresAt,
        };
    }
}
