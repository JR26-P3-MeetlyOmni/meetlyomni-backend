// <copyright file="TokenController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Controller responsible for token operations (refresh, validation, etc.).
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IClientInfoService _clientInfoService;
    private readonly ILogger<TokenController> _logger;

    public TokenController(
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        ILogger<TokenController> logger)
    {
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _logger = logger;
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
            // Get refresh token from cookie
            if (!Request.Cookies.TryGetValue("refresh_token", out var refreshToken) ||
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

            var isDevelopment = HttpContext.RequestServices
                .GetRequiredService<IWebHostEnvironment>().IsDevelopment();

            // Set new Access Token cookie
            var atCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = !isDevelopment,
                SameSite = SameSiteMode.Strict,
                Expires = newTokens.accessTokenExpiresAt,
                Path = "/",
            };

            // Set new Refresh Token cookie
            var rtCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = !isDevelopment,
                SameSite = SameSiteMode.Strict,
                Expires = newTokens.refreshTokenExpiresAt,
                Path = "/api/Token",
            };

            Response.Cookies.Append("access_token", newTokens.accessToken, atCookieOptions);
            Response.Cookies.Append("refresh_token", newTokens.refreshToken, rtCookieOptions);

            // Return response without any token information (tokens are in cookies)
            var response = new LoginResponse
            {
                ExpiresAt = newTokens.accessTokenExpiresAt,
                TokenType = "Bearer",
            };

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Token refresh failed: {Message}", ex.Message);

            // Clear invalid refresh token cookie
            Response.Cookies.Delete("refresh_token", new CookieOptions { Path = "/api/Token" });
            Response.Cookies.Delete("access_token");

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
