// <copyright file="ISignUpService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Members;

namespace MeetlyOmni.Api.Service.SignUpService;
public interface ISignUpService
{
    Task<MemberDto> SignUpAdminAsync(SignUpBindingModel input);
}
