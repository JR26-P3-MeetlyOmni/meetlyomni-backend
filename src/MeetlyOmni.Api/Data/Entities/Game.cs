// <copyright file="Game.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json.Nodes;

using MeetlyOmni.Api.Common.Enums.Game;

namespace MeetlyOmni.Api.Data.Entities;
public class Game
{
    public Guid GameId { get; set; }

    public GameType Type { get; set; }

    public string? Title { get; set; }

    public JsonObject? Config { get; set; }

    public Guid? CreatedBy { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    // Navigation
    public Member? Creator { get; set; }

    public ICollection<EventGameInstance> EventGameInstances { get; set; } = new List<EventGameInstance>();
}
