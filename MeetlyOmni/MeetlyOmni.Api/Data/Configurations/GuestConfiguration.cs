using MeetlyOmni.Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MeetlyOmni.Api.Common.Extensions;

namespace MeetlyOmni.Api.Data.Configurations
{
    public class GuestConfiguration : IEntityTypeConfiguration<Guest>
    {
        public void Configure(EntityTypeBuilder<Guest> builder)
        {
            builder.HasKey(g => g.GuestId);
            builder.Property(g => g.EventId).IsRequired();

            builder.ConfigureString(nameof(Guest.Name), maxLength: 255);
            builder.ConfigureString(nameof(Guest.Company), maxLength: 255, isRequired: false);
            builder.ConfigureString(nameof(Guest.Position), maxLength: 255, isRequired: false);
            builder.ConfigureString(nameof(Guest.AvatarUrl), isRequired: false);
            builder.ConfigureString(nameof(Guest.Bio), isRequired: false);

            builder.ConfigureJsonbObject(nameof(Guest.SocialLinks));

            builder.Property(g => g.Order)
                   .IsRequired(); // 可选加默认值：.HasDefaultValue(0)
        }
    }
}
