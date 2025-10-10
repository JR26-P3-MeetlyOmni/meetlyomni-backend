// <copyright file="SameOrganizationRequirement.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Authorization;

namespace MeetlyOmni.Api.Authorization.Requirements;

/// <summary>
/// Authorization requirement to check if user belongs to the same organization as the resource.
/// </summary>
public class SameOrganizationRequirement : IAuthorizationRequirement
{
    // No additional properties needed
}

