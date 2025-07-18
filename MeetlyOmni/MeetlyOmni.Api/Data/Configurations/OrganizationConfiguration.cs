using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MeetlyOmni.Api.Common.Enums.Organization;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Configurations
{
    public class OrganizationConfiguration : IEntityTypeConfiguration<Organization>
    {
        public void Configure(EntityTypeBuilder<Organization> builder)
        {
            builder.HasKey(o => o.OrgId);

            builder.ConfigureString(nameof(Organization.OrganizationCode), maxLength: 30);
            builder.ConfigureString(nameof(Organization.OrganizationName), maxLength: 100);
            builder.ConfigureString(nameof(Organization.LogoUrl), isRequired: false);
            builder.ConfigureString(nameof(Organization.CoverImageUrl), isRequired: false);
            builder.ConfigureString(nameof(Organization.Description), isRequired: false);
            builder.ConfigureString(nameof(Organization.Location), maxLength: 255, isRequired: false);
            builder.ConfigureString(nameof(Organization.WebsiteUrl), isRequired: false);

            builder.ConfigureJsonbList(nameof(Organization.IndustryTags));

            builder.Property(o => o.FollowerCount)
                   .HasDefaultValue(0);

            builder.Property(o => o.IsVerified)
                   .HasDefaultValue(false);

            builder.ConfigureEnumAsString<PlanType>(
                nameof(Organization.PlanType),
                maxLength: 20,
                defaultValue: PlanType.Free
            );

            builder.Property(o => o.CreatedAt)
                   .HasDefaultValueSql("NOW()");

            builder.Property(o => o.UpdatedAt)
                   .HasDefaultValueSql("NOW()");
        }
    }
}
