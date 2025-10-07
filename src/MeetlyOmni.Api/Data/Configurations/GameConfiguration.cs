// <copyright file="GameConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.Game;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations;
public class GameConfiguration : IEntityTypeConfiguration<Game>
{
    public void Configure(EntityTypeBuilder<Game> builder)
    {
        builder.HasKey(g => g.GameId);

        builder.ConfigureEnumAsString(
            g => g.Type,
            maxLength: 30);

        builder.ConfigureString(g => g.Title, maxLength: 255, isRequired: false);

        builder.ConfigureJsonbObject(g => g.Config);

        builder.Property(g => g.CreatedBy)
               .IsRequired(false);

        builder.Property(g => g.CreatedAt)
               .HasDefaultValueSql("NOW()");

        // Foreign key relationships - CreatedBy points to Member
        builder.HasOne(g => g.Creator)
               .WithMany(m => m.CreatedGames)
               .HasForeignKey(g => g.CreatedBy)
               .OnDelete(DeleteBehavior.SetNull);

        // Navigation to EventGameInstances
        builder.HasMany(g => g.EventGameInstances)
               .WithOne(egi => egi.Game)
               .HasForeignKey(egi => egi.GameId)
               .OnDelete(DeleteBehavior.Cascade);

        // Performance indexes
        builder.HasIndex(g => g.Type)
               .HasDatabaseName("IX_Game_Type");

        builder.HasIndex(g => g.CreatedBy)
               .HasDatabaseName("IX_Game_CreatedBy");

        builder.HasIndex(g => g.CreatedAt)
               .HasDatabaseName("IX_Game_CreatedAt");
    }
}
