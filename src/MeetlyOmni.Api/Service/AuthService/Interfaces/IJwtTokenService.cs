// <copyright file="IJwtTokenService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Models.Auth;

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

public interface IJwtTokenService
{
    Task<TokenResult> GenerateTokenAsync(Member member);
}
