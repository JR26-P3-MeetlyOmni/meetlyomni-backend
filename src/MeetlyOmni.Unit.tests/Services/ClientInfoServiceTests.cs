// <copyright file="ClientInfoServiceTests.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Net;

using FluentAssertions;

using MeetlyOmni.Api.Service.Common;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Moq;

namespace MeetlyOmni.Unit.tests.Services;

public class ClientInfoServiceTests
{
    private readonly IClientInfoService _clientInfoService;

    public ClientInfoServiceTests()
    {
        var loggerMock = new Mock<ILogger<ClientInfoService>>();
        _clientInfoService = new ClientInfoService(loggerMock.Object);
    }

    [Fact]
    public void GetClientInfo_WithUserAgentAndXForwardedFor_ShouldReturnCorrectInfo()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var expectedUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        var expectedIpAddress = "192.168.1.100";

        context.Request.Headers["User-Agent"] = expectedUserAgent;
        context.Request.Headers["X-Forwarded-For"] = expectedIpAddress;

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be(expectedUserAgent);
        ipAddress.Should().Be(expectedIpAddress);
    }

    [Fact]
    public void GetClientInfo_WithUserAgentOnly_ShouldReturnUserAgentAndDefaultIp()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var expectedUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        context.Request.Headers["User-Agent"] = expectedUserAgent;
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be(expectedUserAgent);
        ipAddress.Should().Be("127.0.0.1"); // Default IP for localhost
    }

    [Fact]
    public void GetClientInfo_WithXForwardedForOnly_ShouldReturnDefaultUserAgentAndIp()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var expectedIpAddress = "192.168.1.100";

        context.Request.Headers["X-Forwarded-For"] = expectedIpAddress;

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be(expectedIpAddress);
    }

    [Fact]
    public void GetClientInfo_WithNoHeaders_ShouldReturnDefaults()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be("127.0.0.1");
    }

    [Fact]
    public void GetClientInfo_WithEmptyUserAgent_ShouldReturnUnknownUserAgent()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "";
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be("127.0.0.1");
    }

    [Fact]
    public void GetClientInfo_WithEmptyXForwardedFor_ShouldReturnDefaultIp()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Forwarded-For"] = "";
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be("127.0.0.1");
    }

    [Fact]
    public void GetClientInfo_WithWhitespaceHeaders_ShouldReturnDefaults()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "   ";
        context.Request.Headers["X-Forwarded-For"] = "   ";
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be("127.0.0.1");
    }

    [Theory]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")]
    [InlineData("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")]
    [InlineData("PostmanRuntime/7.29.0")]
    [InlineData("curl/7.68.0")]
    public void GetClientInfo_WithVariousUserAgents_ShouldReturnCorrectUserAgent(string userAgent)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = userAgent;
        context.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        // Act
        var (resultUserAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        resultUserAgent.Should().Be(userAgent);
        ipAddress.Should().Be("127.0.0.1");
    }

    [Theory]
    [InlineData("192.168.1.100")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("8.8.8.8")]
    [InlineData("2001:db8::1")]
    public void GetClientInfo_WithVariousIpAddresses_ShouldReturnCorrectIp(string ipAddress)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Forwarded-For"] = ipAddress;

        // Act
        var (userAgent, resultIpAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        resultIpAddress.Should().Be(ipAddress);
    }

    [Fact]
    public void GetClientInfo_WithMultipleXForwardedFor_ShouldReturnFirstIp()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Forwarded-For"] = "192.168.1.100, 10.0.0.1, 172.16.0.1";

        // Act
        var (userAgent, ipAddress) = _clientInfoService.GetClientInfo(context);

        // Assert
        userAgent.Should().Be("Unknown");
        ipAddress.Should().Be("192.168.1.100");
    }
}
