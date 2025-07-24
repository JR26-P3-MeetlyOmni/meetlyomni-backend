// <copyright file="OrganizationConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Configurations
{
    using MeetlyOmni.Api.Common.Enums.Organization;
    using MeetlyOmni.Api.Common.Extensions;
    using MeetlyOmni.Api.Data.Entities;

    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;

    public class OrganizationConfiguration : IEntityTypeConfiguration<Organization>
    {
        public void Configure(EntityTypeBuilder<Organization> builder)
        {
            builder.HasKey(o => o.OrgId);

            builder.ConfigureString(o => o.OrganizationCode, maxLength: 30);

            // Unique constraint - OrganizationCode must be unique globally
            builder.HasIndex(o => o.OrganizationCode)
                   .IsUnique()
                   .HasDatabaseName("IX_Organization_OrganizationCode");

            builder.ConfigureString(o => o.OrganizationName, maxLength: 100);
            builder.ConfigureString(o => o.LogoUrl, isRequired: false);
            builder.ConfigureString(o => o.CoverImageUrl, isRequired: false);
            builder.ConfigureString(o => o.Description, isRequired: false);
            builder.ConfigureString(o => o.Location, maxLength: 255, isRequired: false);
            builder.ConfigureString(o => o.WebsiteUrl, isRequired: false);

            builder.ConfigureJsonbList(o => o.IndustryTags);

            builder.Property(o => o.FollowerCount)
                   .HasDefaultValue(0);

            builder.Property(o => o.IsVerified)
                   .HasDefaultValue(false);

            builder.ConfigureEnumAsString(
                o => o.PlanType,
                maxLength: 20,
                defaultValue: PlanType.Free);

            builder.Property(o => o.CreatedAt)
                   .HasDefaultValueSql("NOW()");

            builder.Property(o => o.UpdatedAt)
                   .HasDefaultValueSql("NOW()");
        }
    }
}
