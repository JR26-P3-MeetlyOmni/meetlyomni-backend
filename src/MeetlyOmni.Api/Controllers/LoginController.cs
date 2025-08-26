// <copyright file="LoginController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Controller responsible for user login operations.
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly ILoginService _loginService;
    private readonly IClientInfoService _clientInfoService;
    private readonly ILogger<LoginController> _logger;

    public LoginController(
        ILoginService loginService,
        IClientInfoService clientInfoService,
        ILogger<LoginController> logger)
    {
        _loginService = loginService;
        _clientInfoService = clientInfoService;
        _logger = logger;
    }

    /// <summary>
    /// User login endpoint.
    /// </summary>
    /// <param name="request">The login request containing email and password.</param>
    /// <returns>A <see cref="Task{IActionResult}"/> representing the asynchronous operation.</returns>
    [HttpPost]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        try
        {
            // Get client information for security tracking
            var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);

            var response = await _loginService.LoginAsync(request, userAgent, ipAddress);

            // Set Refresh Token in HttpOnly cookie with consistent configuration
            Response.SetRefreshTokenCookie(response.RefreshToken, response.RefreshTokenExpiresAt);

            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";

            // Return access token in response body for frontend to store in memory
            var loginResponse = new LoginResponse
            {
                AccessToken = response.AccessToken, // Include access token in response
                ExpiresAt = response.ExpiresAt,
                TokenType = response.TokenType,
            };

            return Ok(loginResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Login failed for {Email}: {Message}", request.Email, ex.Message);

            return Problem(
                title: "Authentication Failed",
                detail: ex.Message,
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for {Email}", request.Email);

            return Problem(
                title: "Internal Server Error",
                detail: "An unexpected error occurred",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }
}
