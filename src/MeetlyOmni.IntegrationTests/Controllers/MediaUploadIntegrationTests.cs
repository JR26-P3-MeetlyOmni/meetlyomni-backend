using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

using Amazon.S3;
using Amazon.S3.Model;

using MeetlyOmni.Api;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Models.Media;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestPlatform.TestHost;

using Moq;

using Xunit;

namespace MeetlyOmni.IntegrationTests.Controllers;

public class MediaUploadIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly Guid _orgId = Guid.NewGuid();

    public MediaUploadIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            // assume the API project is in a sibling directory named "MeetlyOmni.Api"
            builder.UseContentRoot(Path.Combine(Directory.GetCurrentDirectory(), "../MeetlyOmni.Api"));

            builder.ConfigureServices(services =>
            {
                // Mock S3
                var s3Mock = new Mock<IAmazonS3>();
                s3Mock.Setup(x => x.PutObjectAsync(It.IsAny<PutObjectRequest>(), default))
                      .ReturnsAsync(new PutObjectResponse { ETag = "\"test-etag\"" });
                s3Mock.Setup(x => x.GetPreSignedURL(It.IsAny<GetPreSignedUrlRequest>()))
                      .Returns("https://signed-url.example.com/test.png");
                services.AddSingleton(s3Mock.Object);
            });
        });
    }

    private HttpClient GetAuthenticatedClient()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-jwt-token");
        return client;
    }

    [Fact]
    public async Task Upload_ValidImage_UsesConfiguredBucket()
    {
        var client = GetAuthenticatedClient();
        var content = new MultipartFormDataContent();
        var imageBytes = File.ReadAllBytes("TestAssets/test.png");
        content.Add(new ByteArrayContent(imageBytes), "File", "cover.png");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");
        content.Add(new StringContent("events/covers"), "Folder");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var payload = await response.Content.ReadFromJsonAsync<MediaUploadResponse>();
        Assert.NotNull(payload);
        Assert.Equal("\"test-etag\"", payload!.Etag);
        Assert.Equal("https://signed-url.example.com/test.png", payload.Url);
    }

    [Fact]
    public async Task Upload_MissingFile_Returns400()
    {
        var client = GetAuthenticatedClient();
        var content = new MultipartFormDataContent();
        content.Add(new StringContent(_orgId.ToString()), "OrgId");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_MissingOrgId_Returns400()
    {
        var client = GetAuthenticatedClient();
        var content = new MultipartFormDataContent();
        var imageBytes = File.ReadAllBytes("TestAssets/test.png");
        content.Add(new ByteArrayContent(imageBytes), "File", "cover.png");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_TooLargeFile_Returns413()
    {
        var client = GetAuthenticatedClient();
        var content = new MultipartFormDataContent();
        var largeBytes = new byte[6 * 1024 * 1024]; // 6MB
        content.Add(new ByteArrayContent(largeBytes), "File", "large.png");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal((HttpStatusCode)413, response.StatusCode);
    }

    [Fact]
    public async Task Upload_UnsupportedMediaType_Returns415()
    {
        var client = GetAuthenticatedClient();
        var content = new MultipartFormDataContent();
        var fakeBytes = Encoding.UTF8.GetBytes("not an image");
        content.Add(new ByteArrayContent(fakeBytes), "File", "file.txt");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal((HttpStatusCode)415, response.StatusCode);
    }

    [Fact]
    public async Task Upload_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });
        var content = new MultipartFormDataContent();
        var imageBytes = File.ReadAllBytes("TestAssets/test.png");
        content.Add(new ByteArrayContent(imageBytes), "File", "cover.png");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");

        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

