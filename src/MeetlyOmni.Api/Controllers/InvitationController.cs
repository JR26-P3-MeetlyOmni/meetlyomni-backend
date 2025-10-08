// <copyright file="InvitationController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Asp.Versioning;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Invitation;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common.Interfaces;
using MeetlyOmni.Api.Service.Invitation.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

/// <summary>
/// Controller responsible for member invitation operations.
/// </summary>
[Route("api/v{version:apiVersion}/invitation")]
[ApiController]
[ApiVersion("1.0")]
public class InvitationController : ControllerBase
{
    private readonly IInvitationService _invitationService;
    private readonly ILogger<InvitationController> _logger;
    private readonly ITokenService _tokenService;
    private readonly IClientInfoService _clientInfoService;
    private readonly UserManager<Member> _userManager;

    public InvitationController(
        IInvitationService invitationService,
        ILogger<InvitationController> logger,
        ITokenService tokenService,
        IClientInfoService clientInfoService,
        UserManager<Member> userManager)
    {
        _invitationService = invitationService;
        _logger = logger;
        _tokenService = tokenService;
        _clientInfoService = clientInfoService;
        _userManager = userManager;
    }

    /// <summary>
    /// Invite a member to join the organization.
    /// </summary>
    /// <param name="request">Invitation request containing email and optional message.</param>
    /// <returns>Response indicating success or failure of the invitation.</returns>
    [HttpPost("invite")]
    [Authorize(Roles = RoleConstants.Admin)]
    [ProducesResponseType(typeof(InviteMemberResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> InviteMemberAsync([FromBody] InviteMemberRequest request, CancellationToken ct)
    {
        // Get current user's organization ID
        var currentUserId = User.GetUserId();
        if (currentUserId == null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Unauthorized",
                Detail = "User is not authenticated.",
            });
        }

        var orgId = User.GetOrgId();
        if (orgId == null)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Bad Request",
                Detail = "User is not associated with an organization.",
            });
        }

        var result = await _invitationService.InviteMemberAsync(
            request.Email,
            request.Message,
            orgId.Value,
            currentUserId.Value,
            ct);

        return result.Success ? Ok(result) : BadRequest(result);
    }

    /// <summary>
    /// Accept an invitation to join an organization.
    /// </summary>
    /// <param name="request">Accept invitation request containing email, password, and token.</param>
    /// <returns>Response containing login information if successful.</returns>
    [HttpPost("accept")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(AcceptInvitationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> AcceptInvitationAsync([FromBody] AcceptInvitationRequest request, CancellationToken ct)
    {
        var result = await _invitationService.AcceptInvitationAsync(request, ct);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        // After successful account creation, issue tokens via HttpOnly cookies (same as login)
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is not null)
        {
            var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(HttpContext);
            var tokens = await _tokenService.GenerateTokenPairAsync(user, userAgent, ipAddress, null, ct);

            Response.SetAccessTokenCookie(tokens.accessToken, tokens.accessTokenExpiresAt);
            Response.SetRefreshTokenCookie(tokens.refreshToken, tokens.refreshTokenExpiresAt);
        }

        return Ok(result);
    }

    /// <summary>
    /// Validate an invitation token.
    /// </summary>
    /// <param name="email">Email address.</param>
    /// <param name="token">Invitation token.</param>
    /// <returns>True if the token is valid, false otherwise.</returns>
    [HttpGet("validate")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ValidateInvitationTokenAsync([FromQuery] string email, [FromQuery] string token, CancellationToken ct)
    {
        var isValid = await _invitationService.ValidateInvitationTokenAsync(email, token, ct);
        return Ok(new { IsValid = isValid, Email = email });
    }
}
