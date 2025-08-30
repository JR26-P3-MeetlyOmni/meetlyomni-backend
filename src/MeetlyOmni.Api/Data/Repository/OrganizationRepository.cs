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
        try
        {
            this._context.Organizations.Add(organization);
            await this._context.SaveChangesAsync();
            return organization;
        }
        catch (DbUpdateException ex)
        {
            throw new Exception("An error occurred while adding the organization to the database.", ex);
        }
        catch (Exception ex)
        {
            throw new Exception("An unexpected error occurred.", ex);
        }
    }

    public async Task<bool> OrganizationCodeExistsAsync(string organizationCode)
    {
        return await this._context.Organizations
            .AnyAsync(o => o.OrganizationCode == organizationCode);
    }
}
