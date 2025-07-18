using MeetlyOmni.Api.Common.Enums.Game;
using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MeetlyOmni.Api.Data.Configurations
{
    public class GameConfiguration : IEntityTypeConfiguration<Game>
    {
        public void Configure(EntityTypeBuilder<Game> builder)
        {
            builder.HasKey(g => g.GameId);

            builder.ConfigureEnumAsString<GameType>(
                nameof(Game.Type),
                maxLength: 30
            );

            builder.ConfigureString(nameof(Game.Title), maxLength: 255, isRequired: false);

            builder.ConfigureJsonbObject(nameof(Game.Config));

            builder.Property(g => g.CreatedAt)
                   .HasDefaultValueSql("NOW()");
        }
    }
}
