// <copyright file="IOrganizationRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Repository.Interfaces;

public interface IOrganizationRepository
{
    Task<Organization> AddOrganizationAsync(Organization organization);

    Task<bool> OrganizationCodeExistsAsync(string organizationCode);
}
