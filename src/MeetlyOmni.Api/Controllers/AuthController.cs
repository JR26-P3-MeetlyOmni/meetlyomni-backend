// <copyright file="AuthController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;
using System.Text;

using Asp.Versioning;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Middlewares.Antiforgery;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Models.Member;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Api.Service.EmailService;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

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
    private readonly IEmailSender _emailSender;
    private readonly IConfiguration _config;
    private readonly UserManager<Member> _userManager;

    public AuthController(
        ILoginService loginService,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        IAntiforgery antiforgery,
        ILogger<AuthController> logger,
        ILogoutService logoutService,
        ISignUpService signUpService,
        IEmailSender emailSender,
        IConfiguration config,
        UserManager<Member> userManager)
    {
        _loginService = loginService;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _antiforgery = antiforgery;
        _logger = logger;
        _signUpService = signUpService;
        _logoutService = logoutService;
        _emailSender = emailSender;
        _config = config;
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
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        return Ok(new
        {
            userId = User.FindFirstValue(JwtClaimTypes.Subject),
            email = User.FindFirstValue(JwtClaimTypes.Email),
            orgId = User.FindFirstValue(JwtClaimTypes.OrganizationId),
            message = "Authentication via cookie is working!",
        });
    }

    /// <summary>
    /// User logout endpoint.
    /// </summary>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the asynchronous operation.</returns>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LogoutAsync(CancellationToken ct)
    {
        await _logoutService.LogoutAsync(HttpContext, ct);

        _logger.LogInformation("User logged out successfully.");

        return Ok(new { message = "Logged out successfully" });
    }

    /// <summary>
    /// Registers a new admin user.
    /// </summary>
    /// <param name="request">Signup request model.</param>
    /// <response code="201">Successfully created the user.</response>
    /// <response code="400">Invalid request data.</response>
    /// <response code="409">Email already exists.</response>
    /// <returns>A <see cref="Task"/> Id and email of the new user.</returns>
    [HttpPost("signup")]
    [ProducesResponseType(typeof(Models.Member.MemberDto), 201)]
    [ProducesResponseType(typeof(object), 400)]
    [ProducesResponseType(typeof(object), 409)]
    public async Task<IActionResult> SignUp([FromBody] AdminSignupRequest request)
    {
        var memberDto = await _signUpService.SignUpAdminAsync(request);
        var userIdStr = memberDto.Id.ToString();
        var user = await _userManager.FindByIdAsync(userIdStr);

        // Validate that the user was actually created and found
        if (user == null)
        {
            _logger.LogError("User with ID {UserId} was not found after creation", userIdStr);
            return StatusCode(500, new { message = "User creation succeeded but user could not be retrieved" });
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        
        // Add null check for Frontend:BaseUrl configuration
        var frontendBase = _config["Frontend:BaseUrl"];
        if (string.IsNullOrWhiteSpace(frontendBase))
        {
            _logger.LogError("Frontend:BaseUrl configuration is missing or empty");
            return StatusCode(500, new { message = "Frontend configuration is missing" });
        }
        
        frontendBase = frontendBase.TrimEnd('/');
        var returnUrl = "/login";
        
        // Build the verification URL manually to avoid encoding issues
        var verifyUrl = $"{frontendBase}/verify-email?userId={user.Id}&code={code}&returnUrl={Uri.EscapeDataString(returnUrl)}";
        
        // Log the generated URL for debugging
        _logger.LogInformation("Generated verification URL: {VerifyUrl}", verifyUrl);
        
        // Create HTML message with verification link
        var htmlMessage = $"""
            <p>Hi {user.UserName},</p>
            <p>Please confirm your email by clicking the link below:</p>
            <p><a href="{verifyUrl}">Verify Email</a></p>
            <p>If you did not register, please ignore this email.</p>
            <p>Or click this link:</p>
            <p><a href="{verifyUrl}">{verifyUrl}</a></p>
            """;
        
        // Send email with HTML message
        await _emailSender.SendEmailAsync(user.Email!, "Verify your email", htmlMessage);

        return CreatedAtRoute(
            "GetMemberById",
            new { id = memberDto.Id },
            new { member = memberDto, emailConfirmation = "sent" });
    }

    [HttpGet("members/{id:guid}", Name = "GetMemberById")]
    public async Task<ActionResult<MemberDto>> GetMemberById([FromRoute] Guid id)
    {
        var dto = await _signUpService.GetMemberById(id);
        return dto is null ? NotFound() : Ok(dto);
    }

    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest dto)
    {
        if (string.IsNullOrWhiteSpace(dto.UserId) || string.IsNullOrWhiteSpace(dto.Code))
        {
            return BadRequest(new { message = "Missing userId or code" });
        }

        var user = await _userManager.FindByIdAsync(dto.UserId);
        if (user is null)
        {
            return NotFound(new { message = "User not found" });
        }

        string token;
        try
        {
            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(dto.Code));
        }
        catch
        {
            return BadRequest(new { message = "Invalid code" });
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        return result.Succeeded
            ? Ok(new { message = "Email confirmed" })
            : BadRequest(new
            {
                message = "Confirm failed",
                errors = result.Errors.Select(e => new { e.Code, e.Description }),
            });
    }
}
