// <copyright file="ApplicationDbInitializer.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Linq;

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

using Npgsql;

namespace MeetlyOmni.Api.Data;

public static class ApplicationDbInitializer
{
    public static async Task SeedRolesAsync(IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var logger = serviceProvider.GetRequiredService<ILogger<ApplicationDbInitializerLog>>();

        var roles = new[]
        {
            new { Name = RoleConstants.Admin,     Description = "Company admin - has full access to all features" },
            new { Name = RoleConstants.Employee,  Description = "Company employee - can create events and games" },
        };

        foreach (var roleInfo in roles)
        {
            try
            {
                if (!await roleManager.RoleExistsAsync(roleInfo.Name))
                {
                    logger.LogInformation("Creating role: {RoleName}", roleInfo.Name);

                    var role = new ApplicationRole(roleInfo.Name)
                    {
                        Description = roleInfo.Description,
                    };

                    var result = await roleManager.CreateAsync(role);

                    if (result.Succeeded)
                    {
                        logger.LogInformation("Successfully created role: {RoleName}", roleInfo.Name);
                    }
                    else
                    {
                        // standard DuplicateRoleName
                        if (result.Errors.Any(e => string.Equals(e.Code, "DuplicateRoleName", StringComparison.Ordinal)))
                        {
                            logger.LogDebug("Role concurrently created by another instance: {RoleName}", roleInfo.Name);
                        }
                        else
                        {
                            var errors = string.Join("; ", result.Errors.Select(e => $"{e.Code}:{e.Description}"));
                            logger.LogError("Failed to create role {RoleName}: {Errors}", roleInfo.Name, errors);
                        }
                    }
                }
                else
                {
                    logger.LogDebug("Role already exists: {RoleName}", roleInfo.Name);
                }
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException pg && pg.SqlState == "23505")
            {
                // 23505 = unique_violation
                logger.LogDebug(ex, "Ignore unique constraint (duplicate) for role {RoleName}", roleInfo.Name);
            }
        }
    }
}

// Using for logging purposes
public class ApplicationDbInitializerLog
{
}
