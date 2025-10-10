// <copyright file="IOrganizationResource.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Authorization;

/// <summary>
/// Interface for resources that belong to an organization.
/// </summary>
public interface IOrganizationResource
{
    /// <summary>
    /// Gets the organization ID that owns this resource.
    /// </summary>
    Guid OrgId { get; }
}

