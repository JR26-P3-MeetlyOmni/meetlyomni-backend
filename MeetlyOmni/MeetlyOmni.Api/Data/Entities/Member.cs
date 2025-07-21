// <copyright file="Member.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities
{
    using MeetlyOmni.Api.Common.Enums.Members;

    public class Member
    {
        public string MemberId { get; set; } = string.Empty;

        public Guid OrgId { get; set; }

        public int LocalMemberNumber { get; set; }

        public string Email { get; set; } = string.Empty;

        public string PasswordHash { get; set; } = string.Empty;

        public string? Nickname { get; set; }

        public string? Phone { get; set; }

        public string LanguagePref { get; set; } = "en";

        public List<string> Tags { get; set; } = new ();

        public int Points { get; set; } = 0;

        public MemberStatus Status { get; set; } = MemberStatus.Active;

        public DateTime? LastLogin { get; set; }

        public DateTimeOffset CreatedAt { get; set; }

        public DateTimeOffset UpdatedAt { get; set; }

        // Navigation
        public Organization? Organization { get; set; }

        public ICollection<MemberActivityLog> ActivityLogs { get; set; } = new List<MemberActivityLog>();

        public ICollection<RaffleTicket> RaffleTickets { get; set; } = new List<RaffleTicket>();

        public ICollection<GameRecord> GameRecords { get; set; } = new List<GameRecord>();
    }
}
