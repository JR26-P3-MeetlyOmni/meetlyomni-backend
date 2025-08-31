// <copyright file="ClientInfoService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Net;

using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.Net.Http.Headers;

namespace MeetlyOmni.Api.Service.Common;

/// <summary>
/// Service for extracting client information from HTTP context.
/// </summary>
public class ClientInfoService : IClientInfoService
{
    private readonly ILogger<ClientInfoService> _logger;

    public ClientInfoService(ILogger<ClientInfoService> logger)
    {
        _logger = logger;
    }

    public string GetUserAgent(HttpContext httpContext)
    {
        var userAgent = httpContext.Request.Headers[HeaderNames.UserAgent].ToString();

        // Sanitize and limit length
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return "Unknown";
        }

        // Limit length to prevent database issues
        const int maxLength = 500;
        if (userAgent.Length > maxLength)
        {
            var originalLength = userAgent.Length;
            const int suffixLen = 3; // "..."
            userAgent = userAgent[..Math.Max(0, maxLength - suffixLen)] + "...";
            _logger.LogWarning("User agent truncated from {Original} to {New}", originalLength, userAgent.Length);
        }

        return userAgent;
    }

    public string GetIpAddress(HttpContext httpContext)
    {
        // Priority order for IP detection:
        // 1. X-Forwarded-For (for load balancers/proxies)
        // 2. X-Real-IP (nginx proxy)
        // 3. CF-Connecting-IP (Cloudflare)
        // 4. RemoteIpAddress (direct connection)

        // Check X-Forwarded-For header (most common for load balancers)
        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwardedFor))
        {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // We want the first one (the original client)
            var firstIp = forwardedFor.Split(',')[0].Trim();
            var normalizedFirstIp = NormalizeIpCandidate(firstIp);
            if (IsValidIpAddress(normalizedFirstIp))
            {
                return normalizedFirstIp;
            }
        }

        // Check X-Real-IP header (nginx)
        var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(realIp))
        {
            var normalizedRealIp = NormalizeIpCandidate(realIp);
            if (IsValidIpAddress(normalizedRealIp))
            {
                return normalizedRealIp;
            }
        }

        // Check Cloudflare header
        var cfIp = httpContext.Request.Headers["CF-Connecting-IP"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(cfIp))
        {
            var normalizedCfIp = NormalizeIpCandidate(cfIp);
            if (IsValidIpAddress(normalizedCfIp))
            {
                return normalizedCfIp;
            }
        }

        // Fall back to direct connection IP
        var remoteIp = httpContext.Connection.RemoteIpAddress;
        if (remoteIp != null)
        {
            // Convert IPv4-mapped IPv6 addresses to IPv4
            if (remoteIp.IsIPv4MappedToIPv6)
            {
                remoteIp = remoteIp.MapToIPv4();
            }

            return remoteIp.ToString();
        }

        return "Unknown";
    }

    public (string UserAgent, string IpAddress) GetClientInfo(HttpContext httpContext)
    {
        return (GetUserAgent(httpContext), GetIpAddress(httpContext));
    }

    private static bool IsValidIpAddress(string ipString)
    {
        if (string.IsNullOrWhiteSpace(ipString))
        {
            return false;
        }

        // Try to parse as IP address
        if (!IPAddress.TryParse(ipString, out var ipAddress))
        {
            return false;
        }

        // Reject private/local addresses in production scenarios if needed
        // For now, we accept all valid IP addresses
        return true;
    }

    private static string NormalizeIpCandidate(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return candidate;
        }

        candidate = candidate.Trim();

        // IPv6 in brackets: [2001:db8::1]:port
        if (candidate.StartsWith("[") && candidate.Contains(']'))
        {
            var end = candidate.IndexOf(']');
            return candidate.Substring(1, end - 1);
        }

        // IPv4 with port: 203.0.113.10:443
        if (candidate.Count(c => c == ':') == 1)
        {
            return candidate.Split(':')[0];
        }

        return candidate;
    }
}
