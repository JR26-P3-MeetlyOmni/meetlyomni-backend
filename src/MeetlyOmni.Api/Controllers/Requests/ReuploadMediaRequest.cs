using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

public class ReuploadMediaRequest
{
    [Required]
    public IFormFile File { get; set; }

    [Required]
    public string Key { get; set; }

    [Required]
    public Guid OrgId { get; set; }

    public string? Folder { get; set; }
}
