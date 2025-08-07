// <copyright file="Member.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Data.Entities
{
    using MeetlyOmni.Api.Common.Enums.Members;

    public class Member : IdentityUser<Guid>
    {
        public Guid OrgId { get; set; }

        public int LocalMemberNumber { get; set; }

        public string LanguagePref { get; set; } = "en";

        public List<string> Tags { get; set; } = new ();

        public int Points { get; set; } = 0;

        public MemberStatus Status { get; set; } = MemberStatus.Active;

        public DateTimeOffset? LastLogin { get; set; }

        public DateTimeOffset CreatedAt { get; set; }

        public DateTimeOffset UpdatedAt { get; set; }

        // Navigation
        public Organization? Organization { get; set; }

        public ICollection<MemberActivityLog> ActivityLogs { get; set; } = new List<MemberActivityLog>();

        public ICollection<RaffleTicket> RaffleTickets { get; set; } = new List<RaffleTicket>();

        public ICollection<GameRecord> GameRecords { get; set; } = new List<GameRecord>();

        public ICollection<Game> CreatedGames { get; set; } = new List<Game>();
    }
}
