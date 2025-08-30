// <copyright file="ISignUpService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Models.Member;

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

public interface ISignUpService
{
    Task<MemberDto> SignUpAdminAsync(AdminSignupRequest input);
}
