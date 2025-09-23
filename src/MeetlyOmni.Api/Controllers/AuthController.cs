// <copyright file="AuthController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using Asp.Versioning;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Middlewares.Antiforgery;
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
    private readonly ILogoutService _logoutService;
    private readonly ISignUpService _signUpService;

    public AuthController(
        ILoginService loginService,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<AuthController> logger,
        ILogoutService logoutService,
        ISignUpService signUpService)
    {
        _loginService = loginService;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
        _logoutService = logoutService;
        _signUpService = signUpService;
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
    [SkipAntiforgery]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public IActionResult GetCsrf()
    {
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        Response.SetCsrfTokenCookie(tokens.RequestToken ?? string.Empty);
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
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
        var (accessToken, accessTokenExpiresAt, newRefreshToken, newRefreshTokenExpiresAt) =
            await _tokenService.RefreshTokenPairFromCookiesAsync(HttpContext, userAgent, ipAddress, ct);

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
    [ProducesResponseType(typeof(CurrentUserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public ActionResult<CurrentUserResponse> GetCurrentUser()
    {
        var dto = User.ToCurrentUserResponse();
        if (dto is null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Unauthorized",
                Detail = "User is not authenticated.",
            });
        }

        return Ok(dto);
    }

    /// <summary>
    /// User logout endpoint.
    /// </summary>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the asynchronous operation.</returns>
    [HttpPost("logout")]
    [Authorize]
    [SkipAntiforgery]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LogoutAsync(CancellationToken ct)
    {
        await _logoutService.LogoutAsync(HttpContext, ct);

        _logger.LogInformation("User logged out successfully.");

        return Ok(new { message = "Logged out successfully" });
    }

    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns><summary>
    /// Registers a new admin user.
    /// <param name="request">Signup request model.</param>
    /// <response code="201">Successfully created the user.</response>
    /// <response code="400">Invalid request data.</response>
    /// <response code="409">Email already exists.</response>
    /// <returns>A <see cref="Task"/> Id and email of the new user.</returns>
    [HttpPost("signup")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(Models.Member.MemberDto), 201)]
    [ProducesResponseType(typeof(object), 400)]
    [ProducesResponseType(typeof(object), 409)]
    public async Task<IActionResult> SignUp([FromBody] AdminSignupRequest request)
    {
        var memberDto = await this._signUpService.SignUpAdminAsync(request);

        return StatusCode(StatusCodes.Status201Created, memberDto);
    }
}
