// <copyright file="SignUpBindingModel.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Models.Members;

public class SignUpBindingModel
{
    public string OrganizationName { get; set; }

    public string UserName { get; set; }

    public string Email { get; set; }

    public string Password { get; set; }

    public string PhoneNumber { get; set; }
}
