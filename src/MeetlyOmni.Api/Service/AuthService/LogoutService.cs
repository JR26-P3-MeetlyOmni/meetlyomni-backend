// <copyright file="LogoutService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.Extensions.Logging;

namespace MeetlyOmni.Api.Service.AuthService;

/// <summary>
/// Service responsible for user logout operations.
/// </summary>
public class LogoutService : ILogoutService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<LogoutService> _logger;

    public LogoutService(
        IUnitOfWork unitOfWork,
        ILogger<LogoutService> logger)
    {
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    public async Task LogoutAsync(HttpContext httpContext, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        try
        {
            if (!httpContext.Request.Cookies.TryGetValue(AuthCookieExtensions.CookieNames.RefreshToken, out var refreshToken) ||
                string.IsNullOrWhiteSpace(refreshToken))
            {
                return;
            }

            var tokenHash = ComputeHash(refreshToken);
            var storedToken = await _unitOfWork.RefreshTokens.FindByHashAsync(tokenHash, ct);
            if (storedToken == null)
            {
                return;
            }

            var revokedCount = await _unitOfWork.RefreshTokens.MarkTokenFamilyAsRevokedAsync(storedToken.FamilyId, ct);
            await _unitOfWork.SaveChangesAsync(ct);

            _logger.LogInformation(
                "User {UserId} logged out. Revoked {Count} tokens in family {FamilyId}",
                storedToken.UserId,
                revokedCount,
                storedToken.FamilyId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Logout encountered an error before clearing cookies.");
        }
        finally
        {
            httpContext.Response.DeleteAccessTokenCookie();
            httpContext.Response.DeleteRefreshTokenCookie();
        }
    }

    private static string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashedBytes).ToLowerInvariant();
    }
}
