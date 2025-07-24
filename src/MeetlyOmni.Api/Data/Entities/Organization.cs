// <copyright file="Organization.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities
{
    using MeetlyOmni.Api.Common.Enums.Organization;

    public class Organization
    {
        public Guid OrgId { get; set; }

        public string OrganizationCode { get; set; } = string.Empty;

        public string OrganizationName { get; set; } = string.Empty;

        public string? LogoUrl { get; set; }

        public string? CoverImageUrl { get; set; }

        public string? Description { get; set; }

        public string? Location { get; set; }

        public string? WebsiteUrl { get; set; }

        public List<string>? IndustryTags { get; set; }

        public int FollowerCount { get; set; } = 0;

        public bool IsVerified { get; set; } = false;

        public PlanType PlanType { get; set; }

        public DateTimeOffset CreatedAt { get; set; }

        public DateTimeOffset UpdatedAt { get; set; }

        // Navigation
        public ICollection<Member> Members { get; set; } = new List<Member>();

        public ICollection<Event> Events { get; set; } = new List<Event>();

        public ICollection<RaffleTicket> RaffleTickets { get; set; } = new List<RaffleTicket>();

        public ICollection<MemberActivityLog> ActivityLogs { get; set; } = new List<MemberActivityLog>();

        public ICollection<GameRecord> GameRecords { get; set; } = new List<GameRecord>();
    }
}
