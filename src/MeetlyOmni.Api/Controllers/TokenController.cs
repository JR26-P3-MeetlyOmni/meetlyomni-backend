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
            // CSRF protection: require anti-CSRF header for refresh operations
            var hasAntiCsrfHeader = Request.Headers.ContainsKey("X-Requested-With") ||
                                   Request.Headers.ContainsKey("X-CSRF-Token");

            if (!hasAntiCsrfHeader)
            {
                return Problem(
                    title: "CSRF Protection Required",
                    detail: "Anti-CSRF header (X-Requested-With or X-CSRF-Token) is required for token refresh",
                    statusCode: StatusCodes.Status403Forbidden);
            }

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

            // Set new Refresh Token cookie
            var origin = Request.Headers.Origin.ToString();
            var isCrossSite = !string.IsNullOrEmpty(origin) &&
                              !origin.Contains(Request.Host.Value, StringComparison.OrdinalIgnoreCase);

            var rtCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // SameSite=None Secure is required
                SameSite = isCrossSite ? SameSiteMode.None : SameSiteMode.Lax,
                Path = "/api/Token", // 与API路由保持一致
                Expires = newTokens.refreshTokenExpiresAt,

                // Domain = ".your-domain.com" // Enable when cross-subdomain in production
            };

            Response.Cookies.Append("refresh_token", newTokens.refreshToken, rtCookieOptions);

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
            Response.Cookies.Delete("refresh_token", new CookieOptions { Path = "/api/Token" });

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
