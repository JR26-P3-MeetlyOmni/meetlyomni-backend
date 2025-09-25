// <copyright file="IResetPasswordService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

public interface IResetPasswordService
{
    /// <summary>
    /// Reset user password using a valid token.
    /// </summary>
    /// <param name="email">User email.</param>
    /// <param name="token">Password reset token.</param>
    /// <param name="newPassword">New password.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if password was successfully reset, false otherwise.</returns>
    Task<bool> ResetPasswordAsync(string email, string token, string newPassword, CancellationToken ct = default);
}
