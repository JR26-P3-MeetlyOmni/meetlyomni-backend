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
    private readonly IResetPasswordService _resetPasswordService;

    public AuthController(
        ILoginService loginService,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<AuthController> logger,
        ILogoutService logoutService,
        ISignUpService signUpService,
        IEmailLinkService emailLinkService,
        AccountMailer accountMailer,
        UserManager<Member> userManager,
        IResetPasswordService resetPasswordService)
    {
        _loginService = loginService;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
        _signUpService = signUpService;
        _emailLinkService = emailLinkService;
        _accountMailer = accountMailer;
        _userManager = userManager;
        _resetPasswordService = resetPasswordService;
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
    /// Validate email verification token without confirming the email.
    /// </summary>
    /// <param name="request">Email verification request containing email and token.</param>
    /// <response code="200">Token is valid.</response>
    /// <response code="400">Token is invalid or expired.</response>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the validation result.</returns>
    [HttpPost("validate-email-token")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(TokenValidationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(TokenValidationResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ValidateEmailToken([FromBody] VerifyEmailRequest request, CancellationToken ct)
    {
        var isValid = await _emailLinkService.ValidateEmailVerificationTokenAsync(request.Email, request.Token, ct);

        var response = new TokenValidationResponse
        {
            IsValid = isValid,
            Message = isValid ? "Valid" : "Invalid",
            Email = request.Email,
        };

        return isValid ? Ok(response) : BadRequest(response);
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
            return BadRequest(new { message = "Invalid or expired token" });
        }

        return Ok(new { message = "Email verified", verified = true });
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
        }

        // Always return success to prevent user enumeration
        return Ok(new { message = "Reset link sent if email exists" });
    }

    /// <summary>
    /// Validate password reset token without resetting the password.
    /// </summary>
    /// <param name="request">Verify email request containing email and token.</param>
    /// <response code="200">Token is valid.</response>
    /// <response code="400">Token is invalid or expired.</response>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the validation result.</returns>
    [HttpPost("validate-reset-token")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(TokenValidationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(TokenValidationResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ValidateResetToken([FromBody] VerifyEmailRequest request, CancellationToken ct)
    {
        var isValid = await _emailLinkService.ValidatePasswordResetTokenAsync(request.Email, request.Token, ct);

        var response = new TokenValidationResponse
        {
            IsValid = isValid,
            Message = isValid ? "Valid" : "Invalid",
            Email = request.Email,
        };

        return isValid ? Ok(response) : BadRequest(response);
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
        var isReset = await _resetPasswordService.ResetPasswordAsync(request.Email, request.Token, request.NewPassword, ct);

        if (!isReset)
        {
            return BadRequest(new { message = "Invalid or expired token" });
        }

        return Ok(new { message = "Password reset", reset = true });
    }
}
