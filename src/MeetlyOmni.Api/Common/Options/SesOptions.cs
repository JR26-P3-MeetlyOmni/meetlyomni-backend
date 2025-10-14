// <copyright file="SesOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Common.Options;

public sealed class SesOptions
{
    [Required]
    [EmailAddress]
    public string FromEmail { get; set; } = string.Empty;

    [Required]
    public string Region { get; set; } = "ap-southeast-2";

    public string FromName { get; set; } = "MeetlyOmni";
}
