// <copyright file="MediaUploadResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Media;

public class MediaUploadResponse
{
    public string Key { get; set; } = default!;

    public string Url { get; set; } = default!;

    public string Etag { get; set; } = default!;

    public string ContentType { get; set; } = default!;

    public long Size { get; set; }
}
