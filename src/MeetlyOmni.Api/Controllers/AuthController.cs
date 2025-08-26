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
    /// <summary>
    /// The signup service.
    /// </summary>
    private readonly ISignUpService _signUpService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthController"/> class.
    /// </summary>
    /// <param name="signUpService">The signup service.</param>
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

    /// <summary>
    /// Signup request model for admin registration.
    /// </summary>
    public class AdminSignupRequest
    {
        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        [Required]
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the email address.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the organization name.
        /// </summary>
        [Required]
        public string OrganizationName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the phone number.
        /// </summary>
        [Required]
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
