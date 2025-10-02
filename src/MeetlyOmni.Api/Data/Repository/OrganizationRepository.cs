// <copyright file="OrganizationRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Repository.Interfaces;

using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Data.Repository;

public class OrganizationRepository : IOrganizationRepository
{
    private readonly ApplicationDbContext _context;

    public OrganizationRepository(ApplicationDbContext context)
    {
        this._context = context;
    }

    public async Task<Entities.Organization> AddOrganizationAsync(Entities.Organization organization)
    {
        this._context.Organizations.Add(organization);
        return organization;
    }

    public async Task<bool> OrganizationCodeExistsAsync(string organizationCode)
    {
        return await this._context.Organizations
            .AnyAsync(o => o.OrganizationCode == organizationCode);
    }
}
