// <copyright file="SameOrganizationAuthorizationHandler.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;

namespace MeetlyOmni.Api.Authorization.Handlers;

/// <summary>
/// Authorization handler to check if user belongs to the same organization as the resource.
/// </summary>
/// <typeparam name="TResource">Resource type that implements IOrganizationResource.</typeparam>
public class SameOrganizationAuthorizationHandler<TResource> : AuthorizationHandler<SameOrganizationRequirement, TResource>
    where TResource : IOrganizationResource
{
    private readonly ILogger<SameOrganizationAuthorizationHandler<TResource>> _logger;

    public SameOrganizationAuthorizationHandler(ILogger<SameOrganizationAuthorizationHandler<TResource>> logger)
    {
        _logger = logger;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SameOrganizationRequirement requirement,
        TResource resource)
    {
        // Get user's organization ID from claims
        var userOrgIdClaim = context.User.FindFirst("org_id")?.Value;

        if (string.IsNullOrEmpty(userOrgIdClaim))
        {
            _logger.LogWarning("User does not have orgId claim");
            return Task.CompletedTask;
        }

        if (!Guid.TryParse(userOrgIdClaim, out var userOrgId))
        {
            _logger.LogWarning("Invalid orgId claim format: {OrgIdClaim}", userOrgIdClaim);
            return Task.CompletedTask;
        }

        // Check if user's organization matches resource's organization
        if (resource.OrgId == userOrgId)
        {
            context.Succeed(requirement);
            _logger.LogDebug(
                "User {UserId} authorized to access resource in organization {OrgId}",
                context.User.FindFirst("sub")?.Value,
                userOrgId);
        }
        else
        {
            _logger.LogWarning(
                "User {UserId} attempted to access resource in different organization. User OrgId: {UserOrgId}, Resource OrgId: {ResourceOrgId}",
                context.User.FindFirst("sub")?.Value,
                userOrgId,
                resource.OrgId);
        }

        return Task.CompletedTask;
    }
}

