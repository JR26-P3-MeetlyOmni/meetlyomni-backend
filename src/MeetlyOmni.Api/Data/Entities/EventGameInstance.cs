// <copyright file="EventGameInstance.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities
{
    using System;

    using MeetlyOmni.Api.Common.Enums.EventGameInstance;

    public class EventGameInstance
    {
        public Guid InstanceId { get; set; }

        public Guid EventId { get; set; }

        public Guid GameId { get; set; }

        public string? TitleOverride { get; set; }

        public InstanceStatus Status { get; set; }

        public int? OrderNum { get; set; }

        public DateTimeOffset? StartTime { get; set; }

        public DateTimeOffset? EndTime { get; set; }

        // Navigation
        public Event? Event { get; set; }

        public Game? Game { get; set; }

        public ICollection<GameRecord> GameRecords { get; set; } = new List<GameRecord>();
    }
}
