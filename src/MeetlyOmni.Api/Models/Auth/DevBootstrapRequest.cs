// <copyright file="DevBootstrapRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Auth;

/// <summary>
/// Request payload to bootstrap a development user and organization.
/// </summary>
public class DevBootstrapRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = default!;

    [Required]
    [StringLength(64, MinimumLength = 6)]
    public string Password { get; set; } = default!;

    public string? OrganizationName { get; set; }

    public string? OrganizationCode { get; set; }
}
