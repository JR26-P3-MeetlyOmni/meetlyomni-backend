// <copyright file="CurrentUserResponse.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Auth;

public class CurrentUserResponse
{
    public Guid Id { get; set; }

    public string Email { get; set; } = string.Empty;

    public string UserName { get; set; } = string.Empty;

    public string Role { get; set; } = string.Empty;

    public string OrgId { get; init; } = string.Empty;
}
