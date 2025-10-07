// <copyright file="GameRecordConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations;
public class GameRecordConfiguration : IEntityTypeConfiguration<GameRecord>
{
    public void Configure(EntityTypeBuilder<GameRecord> builder)
    {
        builder.HasKey(r => r.RecordId);
        builder.Property(r => r.InstanceId).IsRequired();
        builder.Property(r => r.OrgId).IsRequired();
        builder.Property(r => r.MemberId).IsRequired();

        builder.ConfigureJsonbObject(r => r.ResponseData);

        builder.Property(r => r.CreatedAt)
               .HasDefaultValueSql("NOW()");

        builder.HasOne(r => r.EventGameInstance)
               .WithMany(i => i.GameRecords)
               .HasForeignKey(r => r.InstanceId);

        builder.HasOne(r => r.Organization)
               .WithMany(o => o.GameRecords)
               .HasForeignKey(r => r.OrgId);

        builder.HasOne(r => r.Member)
               .WithMany(m => m.GameRecords)
               .HasForeignKey(r => r.MemberId);

        // Performance indexes
        builder.HasIndex(r => new { r.InstanceId, r.MemberId })
               .HasDatabaseName("IX_GameRecord_InstanceId_MemberId");

        builder.HasIndex(r => new { r.OrgId, r.CreatedAt })
               .HasDatabaseName("IX_GameRecord_OrgId_CreatedAt");

        builder.HasIndex(r => r.CreatedAt)
               .HasDatabaseName("IX_GameRecord_CreatedAt");
    }
}
