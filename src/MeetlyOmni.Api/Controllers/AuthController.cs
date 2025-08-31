// <copyright file="AuthController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using Asp.Versioning;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Controller responsible for all authentication and authorization operations.
/// </summary>
[Route("api/v{version:apiVersion}/auth")]
[ApiController]
[ApiVersion("1.0")]
public class AuthController : ControllerBase
{
    private readonly ILoginService _loginService;
    private readonly ITokenService _tokenService;
    private readonly IClientInfoService _clientInfoService;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        ILoginService loginService,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<AuthController> logger)
    {
        _loginService = loginService;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    /// <summary>
    /// User login endpoint.
    /// </summary>
    /// <param name="request">The login request containing email and password.</param>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the asynchronous operation.</returns>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginAsync([FromBody] LoginRequest request, CancellationToken ct)
    {
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
        var result = await _loginService.LoginAsync(request, userAgent, ipAddress, ct);

        Response.SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiresAt);
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        _logger.LogInformation("User {Email} logged in.", request.Email);

        return Ok(new LoginResponse
        {
            AccessToken = result.AccessToken,
            ExpiresAt = result.ExpiresAt,
            TokenType = result.TokenType,
        });
    }

    /// <summary>
    /// Get CSRF token for form protection.
    /// </summary>
    /// <returns>CSRF token information.</returns>
    [HttpGet("csrf")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public IActionResult GetCsrf()
    {
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        Response.SetCsrfTokenCookie(tokens.RequestToken!);
        return Ok(new { message = "CSRF token generated" });
    }

    /// <summary>
    /// Refresh access token using refresh token.
    /// </summary>
    /// <returns>New access and refresh tokens.</returns>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshTokenAsync(CancellationToken ct)
    {
        await _antiforgery.ValidateRequestAsync(HttpContext); // 失败 -> 全局 Handler

        if (!Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
            string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new UnauthorizedAppException("Refresh token is missing."); // 交给全局 Handler（可在那边清 Cookie）
        }

        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
        var (accessToken, accessTokenExpiresAt, newRefreshToken, newRefreshTokenExpiresAt) =
            await _tokenService.RefreshTokenPairAsync(refreshToken, userAgent, ipAddress, ct);

        Response.SetRefreshTokenCookie(newRefreshToken, newRefreshTokenExpiresAt);
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        return Ok(new LoginResponse
        {
            AccessToken = accessToken,
            ExpiresAt = accessTokenExpiresAt,
            TokenType = "Bearer",
        });
    }

    /// <summary>
    /// Get current user information from JWT token.
    /// </summary>
    /// <returns>Current user information.</returns>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirstValue(JwtClaimTypes.Subject);
        var email = User.FindFirstValue(JwtClaimTypes.Email);
        var orgId = User.FindFirstValue(JwtClaimTypes.OrganizationId);

        return Ok(new
        {
            userId,
            email,
            orgId,
            message = "Authentication via cookie is working!",
        });
    }

    /// <summary>
    /// User logout endpoint.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public async Task<IActionResult> LogoutAsync(CancellationToken ct)
    {
        var userId = User.FindFirstValue(JwtClaimTypes.Subject);

        if (!Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
            string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogWarning("Logout attempt without refresh token. UserId={UserId}", userId);
            return Unauthorized(new { message = "Refresh token missing" });
        }

        var success = await _tokenService.LogoutAsync(refreshToken, ct);

        if (!success)
        {
            return Unauthorized(new { message = "Invalid or expired refresh token" });
        }

        Response.Cookies.Delete(AuthCookieExtensions.CookieNames.RefreshToken, new CookieOptions { Path = "/" });
        Response.Cookies.Delete(AuthCookieExtensions.CookieNames.CsrfToken, new CookieOptions { Path = "/" });
        Response.Cookies.Delete("XSRF-TOKEN", new CookieOptions { Path = "/" });

        return Ok(new { message = "Logged out successfully" });
    }
}
