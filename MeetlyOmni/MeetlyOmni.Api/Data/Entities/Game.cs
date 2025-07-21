// <copyright file="Game.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities
{
    using System.Text.Json.Nodes;

    using MeetlyOmni.Api.Common.Enums.Game;

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
