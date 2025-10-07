// <copyright file="JwtOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Common.Options;

public class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    [RegularExpression(@"\S+", ErrorMessage = "Issuer cannot be empty or whitespace.")]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    [RegularExpression(@"\S+", ErrorMessage = "Audience cannot be empty or whitespace.")]
    public string Audience { get; set; } = string.Empty;

    [Required]
    [Range(1, 1440, ErrorMessage = "AccessTokenExpirationMinutes must be between 1 and 1440.")]
    public int AccessTokenExpirationMinutes { get; set; } = 15;

    [Required]
    [Range(1, 43200, ErrorMessage = "RefreshTokenExpirationMinutes must be between 1 and 43200 (30 days).")]
    public int RefreshTokenExpirationMinutes { get; set; } = 43200; // 30 days default
}
