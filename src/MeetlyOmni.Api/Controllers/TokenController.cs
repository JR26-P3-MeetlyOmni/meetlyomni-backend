// <copyright file="TokenController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Controller responsible for token operations (refresh, validation, etc.).
/// </summary>
[Route("api/token")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IClientInfoService _clientInfoService;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<TokenController> _logger;

    public TokenController(
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<TokenController> logger)
    {
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    /// <summary>
    /// Get CSRF token for token refresh operations.
    /// </summary>
    /// <returns>CSRF token for client-side storage.</returns>
    [HttpGet("csrf")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public IActionResult GetCsrf()
    {
        try
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);

            // Set CSRF token cookie with consistent configuration
            Response.SetCsrfTokenCookie(tokens.RequestToken!);

            return Ok(new { message = "CSRF token generated successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating CSRF token");
            return Problem(
                title: "CSRF Token Generation Failed",
                detail: "An error occurred while generating the CSRF token",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }

    /// <summary>
    /// Refresh access token using refresh token.
    /// </summary>
    /// <returns>New access and refresh tokens.</returns>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            // CSRF protection: validate antiforgery token
            await _antiforgery.ValidateRequestAsync(HttpContext);

            // Get refresh token from cookie
            if (!Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
                string.IsNullOrWhiteSpace(refreshToken))
            {
                return Problem(
                    title: "Refresh Token Missing",
                    detail: "Refresh token not found in request",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            // Get client information for security tracking
            var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);

            // Refresh the tokens
            var newTokens = await _tokenService.RefreshTokenPairAsync(
                refreshToken,
                userAgent,
                ipAddress);

            // Set new Refresh Token cookie with consistent configuration
            Response.SetRefreshTokenCookie(newTokens.refreshToken, newTokens.refreshTokenExpiresAt);

            // ban cache
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";

            // Return new access token in response body for frontend to store in memory
            var response = new LoginResponse
            {
                AccessToken = newTokens.accessToken, // Include access token in response
                ExpiresAt = newTokens.accessTokenExpiresAt,
                TokenType = "Bearer",
            };

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Token refresh failed: {Message}", ex.Message);

            // Clear invalid refresh token cookie
            Response.DeleteRefreshTokenCookie();

            return Problem(
                title: "Token Refresh Failed",
                detail: ex.Message,
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token refresh");

            return Problem(
                title: "Internal Server Error",
                detail: "An unexpected error occurred",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }
}
