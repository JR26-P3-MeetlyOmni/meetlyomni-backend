// <copyright file="AntiforgeryProtectionOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Middlewares.Antiforgery;

/// <summary>
/// Configuration options for antiforgery protection middleware.
/// </summary>
public sealed class AntiforgeryProtectionOptions
{
    /// <summary>
    /// Gets or sets the cookie names that should trigger CSRF validation.
    /// </summary>
    public string[] CookieNames { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets a custom validation function to determine if CSRF validation should be performed.
    /// </summary>
    public Func<HttpContext, bool>? ShouldValidate { get; set; }
}
