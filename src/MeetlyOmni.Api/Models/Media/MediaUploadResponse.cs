namespace MeetlyOmni.Api.Models.Media;

public class MediaUploadResponse
{
    public string key { get; set; } = default!;
    public string url { get; set; } = default!;
    public string etag { get; set; } = default!;
    public string contentType { get; set; } = default!;
    public long size { get; set; }
}
