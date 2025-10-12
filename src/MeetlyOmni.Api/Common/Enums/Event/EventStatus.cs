// <copyright file="EventStatus.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Text.Json.Serialization;

namespace MeetlyOmni.Api.Common.Enums.Event;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EventStatus
{
    Draft = 0,
    Published = 1,
    Ended = 2,
}
