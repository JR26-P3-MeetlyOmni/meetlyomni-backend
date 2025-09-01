// <copyright file="AntiforgeryProtectionOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;

namespace MeetlyOmni.Api.Middlewares.Antiforgery;

/// <summary>
/// Configuration options for antiforgery protection middleware.
/// </summary>
public sealed class AntiforgeryProtectionOptions
{
    /// <summary>
    /// Gets or sets the cookie names that should trigger CSRF validation.
    /// Defaults to access_token and refresh_token for secure configuration.
    /// </summary>
    public string[] CookieNames { get; set; } =
        new[] { AuthCookieExtensions.CookieNames.AccessToken, AuthCookieExtensions.CookieNames.RefreshToken };

    /// <summary>
    /// Gets or sets a custom validation function to determine if CSRF validation should be performed.
    /// </summary>
    public Func<HttpContext, bool>? ShouldValidate { get; set; }
}
