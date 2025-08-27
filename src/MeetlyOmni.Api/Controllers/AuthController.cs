// <copyright file="AuthController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

using MeetlyOmni.Api.Service.SignUpService;

using Microsoft.AspNetCore.Mvc;

namespace MeetlyOmni.Api.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : Controller
{
    private readonly ISignUpService _signUpService;

    public AuthController(ISignUpService signUpService)
    {
        this._signUpService = signUpService;
    }

    /// <summary>
    /// Registers a new admin user.
    /// </summary>
    /// <param name="request">Signup request model.</param>
    /// <response code="201">Successfully created the user.</response>
    /// <response code="400">Invalid request data.</response>
    /// <response code="409">Email already exists.</response>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    [HttpPost("signup")]
    [ProducesResponseType(typeof(Models.Members.MemberDto), 201)]
    [ProducesResponseType(typeof(object), 400)]
    [ProducesResponseType(typeof(object), 409)]
    public async Task<IActionResult> SignUp([FromBody] AdminSignupRequest request)
    {
        if (!this.ModelState.IsValid)
        {
            return this.BadRequest(this.ModelState);
        }

        try
        {
            var memberDto = await this._signUpService.SignUpAdminAsync(new Models.Members.SignUpBindingModel
            {
                UserName = request.UserName,
                Email = request.Email,
                Password = request.Password,
                OrganizationName = request.OrganizationName,
                PhoneNumber = request.PhoneNumber,
            });

            // Return 201 Created with location header
            return this.CreatedAtAction(nameof(this.SignUp), new { id = memberDto.Id }, memberDto);
        }
        catch (SignUpService.EmailAlreadyExistsException ex)
        {
            // Return 409 Conflict if email already exists
            return this.Conflict(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return this.BadRequest(new { error = ex.Message });
        }
    }

    public class AdminSignupRequest
    {
        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;

        [Required]
        public string OrganizationName { get; set; } = string.Empty;

        [Required]
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
