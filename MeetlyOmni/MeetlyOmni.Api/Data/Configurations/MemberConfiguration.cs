using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MeetlyOmni.Api.Common.Enums.Members;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;

namespace MeetlyOmni.Api.Data.Configurations
{
    public class MemberConfiguration : IEntityTypeConfiguration<Member>
    {
        public void Configure(EntityTypeBuilder<Member> builder)
        {
            builder.HasKey(m => m.MemberId);
            builder.Property(m => m.MemberId)
                   .HasMaxLength(50)
                   .IsRequired();

            builder.Property(m => m.OrgId).IsRequired();
            builder.Property(m => m.LocalMemberNumber).IsRequired();

            builder.ConfigureString(nameof(Member.Email), maxLength: 255);
            builder.ConfigureString(nameof(Member.PasswordHash), maxLength: 255);
            builder.ConfigureString(nameof(Member.Nickname), maxLength: 100, isRequired: false);
            builder.ConfigureString(nameof(Member.Phone), maxLength: 20, isRequired: false);
            builder.ConfigureString(nameof(Member.LanguagePref), maxLength: 10);

            builder.ConfigureJsonbList(nameof(Member.Tags));

            builder.Property(m => m.Points)
                   .HasDefaultValue(0);

            builder.ConfigureEnumAsString<MemberStatus>(
                nameof(Member.Status),
                maxLength: 20,
                defaultValue: MemberStatus.Active
            );

            builder.Property(m => m.CreatedAt)
                   .HasDefaultValueSql("NOW()");

            builder.Property(m => m.UpdatedAt)
                   .HasDefaultValueSql("NOW()");

            // foreign key relationships
            builder.HasOne(m => m.Organization)
                   .WithMany(o => o.Members)
                   .HasForeignKey(m => m.OrgId);
        }
    }
}
