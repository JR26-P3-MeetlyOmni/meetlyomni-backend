using MeetlyOmni.Api.Common.Enums.EventGameInstance;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations
{
    public class EventGameInstanceConfiguration : IEntityTypeConfiguration<EventGameInstance>
    {
        public void Configure(EntityTypeBuilder<EventGameInstance> builder)
        {
            builder.HasKey(x => x.InstanceId);

            builder.Property(x => x.EventId).IsRequired();
            builder.Property(x => x.GameId).IsRequired();

            builder.ConfigureString(nameof(EventGameInstance.TitleOverride), maxLength: 255, isRequired: false);

            builder.ConfigureEnumAsString<InstanceStatus>(
                nameof(EventGameInstance.Status),
                maxLength: 20,
                defaultValue: InstanceStatus.Draft
            );

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
        }
    }
}
