// <copyright file="OrganizationRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Data.Repository.Organization;

public class OrganizationRepository : IOrganizationRepository
{
    private readonly ApplicationDbContext context;

    public OrganizationRepository(ApplicationDbContext context)
    {
        this.context = context;
    }

    public async Task<Entities.Organization> AddOrganizationAsync(Entities.Organization organization)
    {
        try
        {
            this.context.Organizations.Add(organization);
            await this.context.SaveChangesAsync();
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
        return await this.context.Organizations
            .AnyAsync(o => o.OrganizationCode == organizationCode);
    }
}
