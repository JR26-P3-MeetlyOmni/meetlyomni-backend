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
    [NoCacheFilter]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginAsync([FromBody] LoginRequest request, CancellationToken ct)
    {
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
        var result = await _loginService.LoginAsync(request, userAgent, ipAddress, ct);

        Response.SetAccessTokenCookie(result.AccessToken, result.ExpiresAt);
        Response.SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiresAt);

        _logger.LogInformation("User {Email} logged in.", request.Email);

        return Ok(new LoginResponse
        {
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
    [NoCacheFilter]
    [RefreshTokenValidationFilter]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshTokenAsync(CancellationToken ct)
    {
        await _antiforgery.ValidateRequestAsync(HttpContext);

        // Get refresh token from cookie (validated by RefreshTokenValidationFilter)
        var refreshToken = Request.Cookies[AuthCookieExtensions.CookieNames.RefreshToken]!;

        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
        var (accessToken, accessTokenExpiresAt, newRefreshToken, newRefreshTokenExpiresAt) =
            await _tokenService.RefreshTokenPairAsync(refreshToken, userAgent, ipAddress, ct);

        Response.SetAccessTokenCookie(accessToken, accessTokenExpiresAt);
        Response.SetRefreshTokenCookie(newRefreshToken, newRefreshTokenExpiresAt);

        return Ok(new LoginResponse
        {
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
}
