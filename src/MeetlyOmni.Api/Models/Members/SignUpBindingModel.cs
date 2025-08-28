// <copyright file="SignUpBindingModel.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.ComponentModel.DataAnnotations;

namespace MeetlyOmni.Api.Models.Members;

public class SignUpBindingModel
{
    [StringLength(100)]
    required public string OrganizationName { get; set; }

    [StringLength(50)]
    required public string UserName { get; set; }

    [EmailAddress]
    [StringLength(255)]
    required public string Email { get; set; }

    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 6)]
    required public string Password { get; set; }

    [Phone]
    [StringLength(20)]
    required public string PhoneNumber { get; set; }
}
