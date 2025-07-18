using MeetlyOmni.Api.Common.Enums.Event;

namespace MeetlyOmni.Api.Data.Entities
{
    public class Event
    {
        public Guid EventId { get; set; }

        public Guid OrgId { get; set; }

        public string? Title { get; set; }

        public string? Description { get; set; }

        public string? CoverImageUrl { get; set; }

        public DateTimeOffset? StartTime { get; set; }
        public DateTimeOffset? EndTime { get; set; }

        public string? Location { get; set; }

        public string? Language { get; set; }

        public EventStatus Status { get; set; }

        // Navigation
        public Organization? Organization { get; set; }
        public ICollection<Guest> Guests { get; set; } = new List<Guest>();
        public ICollection<EventContentBlock> ContentBlocks { get; set; } = new List<EventContentBlock>();
        public ICollection<EventGameInstance> EventGameInstances { get; set; } = new List<EventGameInstance>();

    }
}
