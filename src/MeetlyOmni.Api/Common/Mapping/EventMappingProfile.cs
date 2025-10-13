// <copyright file="EventMappingProfile.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using AutoMapper;

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Event;

namespace MeetlyOmni.Api.Common.Mapping;

/// <summary>
/// AutoMapper profile for Event entity mappings.
/// </summary>
public class EventMappingProfile : Profile
{
    public EventMappingProfile()
    {
        // UpdateEventRequest -> Event (partial update, ignore null values)
        CreateMap<UpdateEventRequest, Event>()
            .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null));
    }
}
