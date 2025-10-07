// <copyright file="GameRecord.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json.Nodes;

namespace MeetlyOmni.Api.Data.Entities;
public class GameRecord
{
    public Guid RecordId { get; set; }

    public Guid InstanceId { get; set; }

    public Guid MemberId { get; set; }

    public Guid OrgId { get; set; }

    public JsonObject? ResponseData { get; set; }

    public int? Score { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    // Navigation
    public EventGameInstance? EventGameInstance { get; set; }

    public Organization? Organization { get; set; }

    public Member? Member { get; set; }
}
