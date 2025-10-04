// <copyright file="CookieExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Http;

namespace MeetlyOmni.Api.Common.Extensions;

public static class AuthCookieExtensions
{
    // ".meetlyomni.com"
    private static string? _prodDomain;

    public static void ConfigureCookieDomain(string? domain)
    {
        _prodDomain = string.IsNullOrWhiteSpace(domain) ? null : domain;
    }

    private static CookieOptions WithDomain(CookieOptions options)
    {
        if (!string.IsNullOrWhiteSpace(_prodDomain))
        {
            options.Domain = _prodDomain;
        }

        return options;
    }

    public static CookieOptions CreateDeletionCookieOptions()
        => WithDomain(new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.Root,
            Expires = DateTimeOffset.UnixEpoch,
            IsEssential = true,
        });

    public static CookieOptions CreateRefreshTokenCookieOptions(DateTimeOffset expiresAt)
        => WithDomain(new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.Root,
            Expires = expiresAt,
            IsEssential = true,
        });

    public static CookieOptions CreateAccessTokenCookieOptions(DateTimeOffset expiresAt)
        => WithDomain(new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.Root,
            Expires = expiresAt,
            IsEssential = true,
        });

    public static CookieOptions CreateCsrfTokenCookieOptions()
        => WithDomain(new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = CookiePaths.Root,
            IsEssential = true,
        });

    public static void SetRefreshTokenCookie(this HttpResponse resp, string token, DateTimeOffset expiresAt)
        => resp.Cookies.Append(CookieNames.RefreshToken, token, CreateRefreshTokenCookieOptions(expiresAt));

    public static void SetAccessTokenCookie(this HttpResponse resp, string token, DateTimeOffset expiresAt)
        => resp.Cookies.Append(CookieNames.AccessToken, token, CreateAccessTokenCookieOptions(expiresAt));

    public static void SetCsrfTokenCookie(this HttpResponse resp, string csrfToken)
        => resp.Cookies.Append(CookieNames.CsrfToken, csrfToken, CreateCsrfTokenCookieOptions());

    public static void DeleteRefreshTokenCookie(this HttpResponse resp)
        => resp.Cookies.Delete(CookieNames.RefreshToken, CreateDeletionCookieOptions());

    public static void DeleteAccessTokenCookie(this HttpResponse resp)
        => resp.Cookies.Delete(CookieNames.AccessToken, CreateDeletionCookieOptions());

    public static class CookieNames
    {
        public const string RefreshToken = "refresh_token";
        public const string AccessToken = "access_token";
        public const string CsrfToken = "XSRF-TOKEN";
    }

    public static class CookiePaths
    {
        public const string Root = "/";
    }
}
