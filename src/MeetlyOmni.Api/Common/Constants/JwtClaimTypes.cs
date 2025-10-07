// <copyright file="JwtClaimTypes.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Common.Constants;

/// <summary>
/// JWT claim type constants to avoid magic strings.
/// </summary>
public static class JwtClaimTypes
{
    /// <summary>
    /// Subject claim (user ID).
    /// </summary>
    public const string Subject = "sub";

    /// <summary>
    /// Email claim.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// Organization ID claim.
    /// </summary>
    public const string OrganizationId = "org_id";

    /// <summary>
    /// User name claim.
    /// </summary>
    public const string Name = "name";

    /// <summary>
    /// Role claim.
    /// </summary>
    public const string Role = "role";
}
