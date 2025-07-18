using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MeetlyOmni.Api.Common.Enums.RaffleTicket;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Configurations
{
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

            builder.ConfigureEnumAsString<RaffleTicketStatus>(
                nameof(RaffleTicket.Status),
                maxLength: 20,
                columnType: "varchar(20)",
                defaultValue: RaffleTicketStatus.Unused
            );

            builder.ConfigureNullableEnumAsString<RaffleIssuedSource>(
                nameof(RaffleTicket.IssuedBy),
                maxLength: 20
            );

            builder.HasOne(r => r.Member)
                   .WithMany(m => m.RaffleTickets)
                   .HasForeignKey(r => r.MemberId);

            builder.HasOne(r => r.Organization)
                   .WithMany(o => o.RaffleTickets)
                   .HasForeignKey(r => r.OrgId);
        }
    }
}
