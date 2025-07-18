using MeetlyOmni.Api.Common.Enums.Game;
using System.Text.Json.Nodes;

namespace MeetlyOmni.Api.Data.Entities
{
    public class Game
    {
        public Guid GameId { get; set; }

        public GameType Type { get; set; }

        public string? Title { get; set; }

        public JsonObject? Config { get; set; }

        public Guid? CreatedBy { get; set; }

        public DateTimeOffset CreatedAt { get; set; }

        // Navigation
        public ICollection<EventGameInstance> EventGameInstances { get; set; } = new List<EventGameInstance>();
    }
}
