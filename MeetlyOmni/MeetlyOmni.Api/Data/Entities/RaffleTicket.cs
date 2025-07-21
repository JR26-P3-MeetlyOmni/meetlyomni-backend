// <copyright file="RaffleTicket.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Data.Entities
{
    using MeetlyOmni.Api.Common.Enums.RaffleTicket;

    public class RaffleTicket
    {
        public Guid TicketId { get; set; }

        public Guid OrgId { get; set; }

        public string MemberId { get; set; } = string.Empty;

        public RaffleIssuedSource? IssuedBy { get; set; }

        public RaffleTicketStatus Status { get; set; } = RaffleTicketStatus.Unused;

        public DateTimeOffset IssueTime { get; set; }

        // Navigation
        public Member? Member { get; set; }

        public Organization? Organization { get; set; }
    }
}
