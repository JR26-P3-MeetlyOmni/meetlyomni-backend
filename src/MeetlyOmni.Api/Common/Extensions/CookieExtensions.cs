// <copyright file="CookieExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Http;

namespace MeetlyOmni.Api.Common.Extensions;

/// <summary>
/// Extension methods for cookie configuration.
/// </summary>
public static class AuthCookieExtensions
{
    public static CookieOptions CreateRefreshTokenCookieOptions(DateTimeOffset expiresAt)
        => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.TokenApi,
            Expires = expiresAt,

            // Domain = ".your-domain.com"   // production; localhost should not be set
        };

    public static CookieOptions CreateCsrfTokenCookieOptions()
        => new()
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.TokenApi,
        };

    public static void SetRefreshTokenCookie(this HttpResponse resp, string token, DateTimeOffset expiresAt)
        => resp.Cookies.Append(CookieNames.RefreshToken, token, CreateRefreshTokenCookieOptions(expiresAt));

    public static void SetCsrfTokenCookie(this HttpResponse resp, string csrfToken)
        => resp.Cookies.Append(CookieNames.CsrfToken, csrfToken, CreateCsrfTokenCookieOptions());

    public static void DeleteRefreshTokenCookie(this HttpResponse resp)
        => resp.Cookies.Delete(CookieNames.RefreshToken, new CookieOptions { Path = CookiePaths.TokenApi });

    public static class CookieNames
    {
        public const string RefreshToken = "refresh_token";
        public const string CsrfToken = "XSRF-TOKEN";
    }

    public static class CookiePaths
    {
        public const string TokenApi = "/api/token";
    }
}
