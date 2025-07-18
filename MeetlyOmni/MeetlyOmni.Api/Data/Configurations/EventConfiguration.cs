using MeetlyOmni.Api.Common.Enums.Event;
using MeetlyOmni.Api.Data.Entities;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using MeetlyOmni.Api.Common.Extensions;

public class EventConfiguration : IEntityTypeConfiguration<Event>
{
    public void Configure(EntityTypeBuilder<Event> builder)
    {
        builder.HasKey(e => e.EventId);

        builder.Property(e => e.OrgId).IsRequired();

        builder.ConfigureString(nameof(Event.Title), maxLength: 255, isRequired: false);
        builder.ConfigureString(nameof(Event.Location), maxLength: 255, isRequired: false);
        builder.ConfigureString(nameof(Event.Language), maxLength: 10, isRequired: false);

        builder.ConfigureEnumAsString<EventStatus>(
            nameof(Event.Status),
            maxLength: 20,
            defaultValue: EventStatus.Draft
        );
    }
}
