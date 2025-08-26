// <copyright file="Guest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json.Nodes;

namespace MeetlyOmni.Api.Data.Entities;
public class Guest
{
    public Guid GuestId { get; set; }

    public Guid EventId { get; set; }

    public string Name { get; set; } = string.Empty;

    public string? AvatarUrl { get; set; }

    public string? Bio { get; set; }

    public string? Company { get; set; }

    public string? Position { get; set; }

    public JsonObject? SocialLinks { get; set; }

    public int Order { get; set; }

    // Navigation
    public Event? Event { get; set; }
}
