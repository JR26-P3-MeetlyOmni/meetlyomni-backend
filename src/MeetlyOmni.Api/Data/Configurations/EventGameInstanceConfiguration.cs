// <copyright file="EventGameInstanceConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.EventGameInstance;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations;
public class EventGameInstanceConfiguration : IEntityTypeConfiguration<EventGameInstance>
{
    public void Configure(EntityTypeBuilder<EventGameInstance> builder)
    {
        builder.HasKey(x => x.InstanceId);

        builder.Property(x => x.EventId).IsRequired();
        builder.Property(x => x.GameId).IsRequired();

        builder.ConfigureString(x => x.TitleOverride, maxLength: 255, isRequired: false);

        builder.ConfigureEnumAsString(
            x => x.Status,
            maxLength: 20,
            defaultValue: InstanceStatus.Draft);

        // Relationships
        builder.HasOne(x => x.Event)
               .WithMany(e => e.EventGameInstances)
               .HasForeignKey(x => x.EventId);

        builder.HasOne(x => x.Game)
               .WithMany(g => g.EventGameInstances)
               .HasForeignKey(x => x.GameId);

        builder.HasMany(x => x.GameRecords)
               .WithOne(gr => gr.EventGameInstance)
               .HasForeignKey(gr => gr.InstanceId)
               .OnDelete(DeleteBehavior.Cascade);

        // Performance indexes
        builder.HasIndex(x => x.Status)
               .HasDatabaseName("IX_EventGameInstance_Status");

        builder.HasIndex(x => new { x.EventId, x.OrderNum })
               .HasDatabaseName("IX_EventGameInstance_EventId_OrderNum");

        builder.HasIndex(x => new { x.EventId, x.Status })
               .HasDatabaseName("IX_EventGameInstance_EventId_Status");
    }
}
