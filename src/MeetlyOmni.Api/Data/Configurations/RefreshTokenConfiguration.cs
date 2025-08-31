// <copyright file="RefreshTokenConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");

        builder.HasKey(rt => rt.Id);

        builder.Property(rt => rt.TokenHash)
            .IsRequired()
            .HasMaxLength(64); // SHA256 hex length

        builder.Property(rt => rt.UserAgent)
            .HasMaxLength(500);

        builder.Property(rt => rt.IpAddress)
            .HasMaxLength(45); // IPv6 max length

        builder.Property(rt => rt.ReplacedByHash)
            .HasMaxLength(64);

        // Indexes for performance
        builder.HasIndex(rt => rt.TokenHash)
            .IsUnique();

        builder.HasIndex(rt => rt.UserId);

        builder.HasIndex(rt => rt.FamilyId);

        builder.HasIndex(rt => rt.ExpiresAt);

        // Foreign key relationship
        builder.HasOne(rt => rt.User)
            .WithMany()
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        // Convert computed property for EF Core
        builder.Ignore(rt => rt.IsActive);
        builder.Ignore(rt => rt.IsReplaced);
    }
}
