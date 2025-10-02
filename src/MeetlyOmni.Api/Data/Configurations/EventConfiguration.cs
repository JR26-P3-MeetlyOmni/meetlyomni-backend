// <copyright file="EventConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.Event;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

public class EventConfiguration : IEntityTypeConfiguration<Event>
{
    public void Configure(EntityTypeBuilder<Event> builder)
    {
        builder.HasKey(e => e.EventId);

        builder.Property(e => e.OrgId).IsRequired();

        builder.ConfigureString(e => e.Title, maxLength: 255, isRequired: false);
        builder.ConfigureString(e => e.Location, maxLength: 255, isRequired: false);
        builder.ConfigureString(e => e.Language, maxLength: 10, isRequired: false);

        builder.ConfigureEnumAsString(
            e => e.Status,
            maxLength: 20,
            defaultValue: EventStatus.Draft);

        builder.Property(e => e.CreatedAt)
               .HasDefaultValueSql("NOW()");

        builder.Property(e => e.UpdatedAt)
               .HasDefaultValueSql("NOW()");

        // Foreign key relationships
        builder.HasOne(e => e.Organization)
               .WithMany(o => o.Events)
               .HasForeignKey(e => e.OrgId);

        // Performance indexes
        builder.HasIndex(e => e.Status)
               .HasDatabaseName("IX_Event_Status");

        // Composite index for OrgId and Status
        builder.HasIndex(e => new { e.OrgId, e.Status })
               .HasDatabaseName("IX_Event_OrgId_Status");

        builder.HasIndex(e => e.StartTime)
               .HasDatabaseName("IX_Event_StartTime");
    }
}
