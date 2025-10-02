// <copyright file="EventContentBlock.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json.Nodes;

using MeetlyOmni.Api.Common.Enums.EventContentBlock;

namespace MeetlyOmni.Api.Data.Entities;
public class EventContentBlock
{
    public Guid BlockId { get; set; }

    public Guid EventId { get; set; }

    public BlockType BlockType { get; set; }

    public string? Title { get; set; }

    public JsonObject? Content { get; set; }

    public int? OrderNum { get; set; }

    public bool? Visible { get; set; }

    // Navigation
    public Event? Event { get; set; }
}
