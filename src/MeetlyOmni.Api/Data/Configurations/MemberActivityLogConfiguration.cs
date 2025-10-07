// <copyright file="MemberActivityLogConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.MemberActivityLog;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations;
public class MemberActivityLogConfiguration : IEntityTypeConfiguration<MemberActivityLog>
{
    public void Configure(EntityTypeBuilder<MemberActivityLog> builder)
    {
        builder.HasKey(x => x.LogId);

        builder.Property(x => x.MemberId)
               .IsRequired();

        builder.Property(x => x.OrgId)
               .IsRequired();

        builder.ConfigureEnumAsString(
            x => x.EventType,
            maxLength: 50,
            columnType: "varchar(50)");

        builder.ConfigureJsonbObject(x => x.EventDetail);

        builder.Property(x => x.CreatedAt)
               .HasDefaultValueSql("NOW()");

        // foreign key relationships
        builder.HasOne(x => x.Member)
               .WithMany(m => m.ActivityLogs)
               .HasForeignKey(x => x.MemberId);

        builder.HasOne(x => x.Organization)
               .WithMany(o => o.ActivityLogs)
               .HasForeignKey(x => x.OrgId);
    }
}
