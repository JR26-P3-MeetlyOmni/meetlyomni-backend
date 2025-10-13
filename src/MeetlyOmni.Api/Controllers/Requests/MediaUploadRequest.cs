// <copyright file="MediaUploadRequest.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Http;

namespace MeetlyOmni.Api.Controllers.Requests;

public class MediaUploadRequest
{
    [Required]
    public IFormFile File { get; set; } = default!;

    [Required]
    public Guid OrgId { get; set; }

    public string? Folder { get; set; }
}
