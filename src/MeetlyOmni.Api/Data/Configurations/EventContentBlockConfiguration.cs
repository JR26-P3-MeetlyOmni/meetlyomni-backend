// <copyright file="EventContentBlockConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Configurations
{
    using MeetlyOmni.Api.Common.Enums.EventContentBlock;
    using MeetlyOmni.Api.Common.Extensions;
    using MeetlyOmni.Api.Data.Entities;

    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;

    public class EventContentBlockConfiguration : IEntityTypeConfiguration<EventContentBlock>
    {
        public void Configure(EntityTypeBuilder<EventContentBlock> builder)
        {
            builder.HasKey(b => b.BlockId);
            builder.Property(b => b.EventId).IsRequired();

            builder.ConfigureEnumAsString(
                b => b.BlockType,
                maxLength: 30,
                isRequired: true);

            builder.ConfigureString(b => b.Title, maxLength: 255, isRequired: false);

            builder.ConfigureJsonbObject(b => b.Content);

            builder.Property(b => b.OrderNum)
                   .HasDefaultValue(0);

            builder.Property(b => b.Visible)
                   .HasDefaultValue(true);

            // Foreign key relationships
            builder.HasOne(b => b.Event)
                   .WithMany(e => e.ContentBlocks)
                   .HasForeignKey(b => b.EventId);

            // Performance indexes
            builder.HasIndex(b => new { b.EventId, b.OrderNum })
                   .HasDatabaseName("IX_EventContentBlock_EventId_OrderNum");

            builder.HasIndex(b => new { b.EventId, b.Visible })
                   .HasDatabaseName("IX_EventContentBlock_EventId_Visible");

            builder.HasIndex(b => b.BlockType)
                   .HasDatabaseName("IX_EventContentBlock_BlockType");
        }
    }
}
