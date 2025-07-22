// <copyright file="RaffleTicketConfiguration.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Configurations
{
    using MeetlyOmni.Api.Common.Enums.RaffleTicket;
    using MeetlyOmni.Api.Common.Extensions;
    using MeetlyOmni.Api.Data.Entities;

    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;

    public class RaffleTicketConfiguration : IEntityTypeConfiguration<RaffleTicket>
    {
        public void Configure(EntityTypeBuilder<RaffleTicket> builder)
        {
            builder.HasKey(x => x.TicketId);

            builder.Property(x => x.OrgId).IsRequired();

            builder.Property(x => x.MemberId)
                   .IsRequired()
                   .HasMaxLength(50);

            builder.Property(x => x.IssueTime)
                   .HasDefaultValueSql("NOW()");

            builder.ConfigureEnumAsString(
                x => x.Status,
                maxLength: 20,
                columnType: "varchar(20)",
                defaultValue: RaffleTicketStatus.Unused);

            builder.ConfigureNullableEnumAsString(
                x => x.IssuedBy,
                maxLength: 20);

            builder.HasOne(r => r.Member)
                   .WithMany(m => m.RaffleTickets)
                   .HasForeignKey(r => r.MemberId);

            builder.HasOne(r => r.Organization)
                   .WithMany(o => o.RaffleTickets)
                   .HasForeignKey(r => r.OrgId);
        }
    }
}
