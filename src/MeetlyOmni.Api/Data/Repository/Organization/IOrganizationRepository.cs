// <copyright file="IOrganizationRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Repository.Organization;

public interface IOrganizationRepository
{
    Task<Entities.Organization> AddOrganizationAsync(Entities.Organization organization);

    Task<bool> OrganizationCodeExistsAsync(string organizationCode);
}
