// <copyright file="AuthController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using Asp.Versioning;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Middlewares.Antiforgery;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Api.Service.Email;
using MeetlyOmni.Api.Service.Email.Interfaces;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
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
    private readonly IEmailLinkService _emailLinkService;
    private readonly AccountMailer _accountMailer;
    private readonly UserManager<Member> _userManager;

    public AuthController(
        ILoginService loginService,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<AuthController> logger,
        ISignUpService signUpService,
        IEmailLinkService emailLinkService,
        AccountMailer accountMailer,
        UserManager<Member> userManager)
        ILogoutService logoutService)
    {
        _loginService = loginService;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
        _logoutService = logoutService;
        _signUpService = signUpService;
        _emailLinkService = emailLinkService;
        _accountMailer = accountMailer;
        _userManager = userManager;
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

    /// <summary>
    /// Verify user's email address using the token from verification email.
    /// </summary>
    /// <param name="request">Email verification request containing email and token.</param>
    /// <response code="200">Email successfully verified.</response>
    /// <response code="400">Invalid request data or verification failed.</response>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the verification result.</returns>
    [HttpPost("verify-email")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request, CancellationToken ct)
    {
        var isVerified = await _emailLinkService.ValidateAndConfirmEmailAsync(request.Email, request.Token, ct);

        if (!isVerified)
        {
            _logger.LogWarning("Email verification failed for {Email}", request.Email);
            return BadRequest(new { message = "Email verification failed. The token may be invalid or expired." });
        }

        _logger.LogInformation("Email successfully verified for {Email}", request.Email);

        return Ok(new
        {
            message = "Email successfully verified. You can now log in to your account.",
            email = request.Email,
            verified = true,
        });
    }

    /// <summary>
    /// Request password reset email for a user.
    /// </summary>
    /// <param name="request">Forgot password request containing email.</param>
    /// <response code="200">Password reset email sent (if email exists).</response>
    /// <response code="400">Invalid request data.</response>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the operation result.</returns>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken ct)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user != null && user.EmailConfirmed)
        {
            await _accountMailer.SendResetPasswordAsync(user, ct);
            _logger.LogInformation("Password reset email sent to {Email}", request.Email);
        }
        else
        {
            _logger.LogWarning("Password reset requested for non-existent or unconfirmed email: {Email}", request.Email);
        }

        // Always return success to prevent user enumeration
        return Ok(new
        {
            message = "If the email address exists and is verified, a password reset link has been sent.",
            email = request.Email,
        });
    }

    /// <summary>
    /// Reset user password using token from password reset email.
    /// </summary>
    /// <param name="request">Password reset request containing email, token, and new password.</param>
    /// <response code="200">Password successfully reset.</response>
    /// <response code="400">Invalid request data or password reset failed.</response>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the reset result.</returns>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken ct)
    {
        var isReset = await _emailLinkService.ResetPasswordAsync(request.Email, request.Token, request.NewPassword, ct);

        if (!isReset)
        {
            _logger.LogWarning("Password reset failed for {Email}", request.Email);
            return BadRequest(new { message = "Password reset failed. The token may be invalid or expired." });
        }

        _logger.LogInformation("Password successfully reset for {Email}", request.Email);

        return Ok(new
        {
            message = "Password has been successfully reset. You can now log in with your new password.",
            email = request.Email,
            reset = true,
        });
    }
}
