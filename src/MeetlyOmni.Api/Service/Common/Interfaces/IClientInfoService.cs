// <copyright file="IClientInfoService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Service.Common.Interfaces;

/// <summary>
/// Service for extracting client information from HTTP context.
/// </summary>
public interface IClientInfoService
{
    string GetUserAgent(HttpContext httpContext);

    string GetIpAddress(HttpContext httpContext);

    (string UserAgent, string IpAddress) GetClientInfo(HttpContext httpContext);
}
