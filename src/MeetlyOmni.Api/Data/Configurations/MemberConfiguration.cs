// <copyright file="MemberConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Configurations
{
    using MeetlyOmni.Api.Common.Enums.Members;
    using MeetlyOmni.Api.Common.Extensions;
    using MeetlyOmni.Api.Data.Entities;

    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;

    public class MemberConfiguration : IEntityTypeConfiguration<Member>
    {
        public void Configure(EntityTypeBuilder<Member> builder)
        {
            // Primary key - UUID
            builder.HasKey(m => m.Id);
            builder.Property(m => m.Id)
                   .HasDefaultValueSql("gen_random_uuid()")
                   .IsRequired();

            builder.Property(m => m.OrgId).IsRequired();
            builder.Property(m => m.LocalMemberNumber).IsRequired();

            builder.ConfigureString(m => m.Email, maxLength: 255);
            builder.ConfigureString(m => m.PasswordHash, maxLength: 255);
            builder.ConfigureString(m => m.Nickname, maxLength: 100, isRequired: false);
            builder.ConfigureString(m => m.Phone, maxLength: 20, isRequired: false);
            builder.ConfigureString(m => m.LanguagePref, maxLength: 10);

            builder.ConfigureJsonbList(m => m.Tags);

            builder.Property(m => m.Points)
                   .HasDefaultValue(0);

            builder.ConfigureEnumAsString(
                m => m.Status,
                maxLength: 20,
                defaultValue: MemberStatus.Active);

            builder.Property(m => m.CreatedAt)
                   .HasDefaultValueSql("NOW()");

            builder.Property(m => m.UpdatedAt)
                   .HasDefaultValueSql("NOW()");

            // foreign key relationships
            builder.HasOne(m => m.Organization)
                   .WithMany(o => o.Members)
                   .HasForeignKey(m => m.OrgId);

            // Business unique constraints - these are the natural keys for SaaS login
            builder.HasIndex(m => new { m.OrgId, m.LocalMemberNumber })
                   .IsUnique()
                   .HasDatabaseName("UK_Member_Org_LocalNumber");

            builder.HasIndex(m => new { m.OrgId, m.Email })
                   .IsUnique()
                   .HasDatabaseName("UK_Member_Org_Email");

            // Performance optimization indexes
            builder.HasIndex(m => m.Status)
                   .HasDatabaseName("IX_Member_Status");

            builder.HasIndex(m => m.CreatedAt)
                   .HasDatabaseName("IX_Member_CreatedAt");

            builder.HasIndex(m => new { m.OrgId, m.Status })
                   .HasDatabaseName("IX_Member_OrgId_Status");
        }
    }
}
