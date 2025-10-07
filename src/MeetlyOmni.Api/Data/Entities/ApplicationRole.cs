// <copyright file="ApplicationRole.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Data.Entities;

public class ApplicationRole : IdentityRole<Guid>
{
    public ApplicationRole()
        : base()
    {
    }

    public ApplicationRole(string roleName)
        : base(roleName)
    {
    }

    public string? Description { get; set; }
}
