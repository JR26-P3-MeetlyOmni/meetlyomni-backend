using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Controllers.Requests
{
    public class MediaUploadRequest
    {
        [Required]
        public IFormFile File { get; set; } = default!;

        [Required]
        public Guid OrgId { get; set; }

        public string? Folder { get; set; }
    }
}
