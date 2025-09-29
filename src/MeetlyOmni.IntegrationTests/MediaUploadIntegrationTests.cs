using System.Net;
using System.Net.Http.Headers;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.AspNetCore.Mvc.Testing; // Fixes WebApplicationFactory<>.
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Moq;
using Xunit;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using System.Net.Http.Json;
using System.Text;
using MeetlyOmni.Api.Models.Media; // Fixes Program reference (ensure your Program class is in this namespace)

namespace MeetlyOmni.IntegrationTests;

public class MediaUploadIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly Guid _orgId = Guid.NewGuid();
    private readonly AWSOptions _awsOptions;

    public MediaUploadIntegrationTests(WebApplicationFactory<Program> factory)
    {
        // Load configuration from appsettings.json
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .Build();

        _awsOptions = config.GetSection("AWS").Get<AWSOptions>() ?? new AWSOptions { BucketName = "meetlyomni_media", Region = Amazon.RegionEndpoint.APEast1 };

        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                var s3Mock = new Mock<IAmazonS3>();
                s3Mock.Setup(x => x.PutObjectAsync(It.Is<PutObjectRequest>(r => r.BucketName == _awsOptions.BucketName), default))
                    .ReturnsAsync(new PutObjectResponse { ETag = "\"test-etag\"" });
                s3Mock.Setup(x => x.GetPreSignedURL(It.Is<GetPreSignedUrlRequest>(r => r.BucketName == _awsOptions.BucketName)))
                    .Returns("https://signed-url.example.com/test.png");
                services.AddSingleton(s3Mock.Object);
            });
        });
    }

    private HttpClient GetAuthenticatedClient()
    {
        var client = _factory.CreateClient();
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
        Assert.Contains("cover.png", payload!.key);
        Assert.Equal("https://signed-url.example.com/test.png", payload.url);
        Assert.Equal("\"test-etag\"", payload.etag);
        Assert.Equal("image/png", payload.contentType);
        Assert.True(payload.size > 0);
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
        var client = _factory.CreateClient();
        var content = new MultipartFormDataContent();
        var imageBytes = File.ReadAllBytes("TestAssets/test.png");
        content.Add(new ByteArrayContent(imageBytes), "File", "cover.png");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");
        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Upload_S3Failure_Returns500()
    {
        var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                var s3Mock = new Mock<IAmazonS3>();
                s3Mock.Setup(x => x.PutObjectAsync(It.IsAny<PutObjectRequest>(), default))
                    .ThrowsAsync(new Exception("S3 error"));
                services.AddSingleton(s3Mock.Object);
            });
        });
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-jwt-token");
        var content = new MultipartFormDataContent();
        var imageBytes = File.ReadAllBytes("TestAssets/test.png");
        content.Add(new ByteArrayContent(imageBytes), "File", "cover.png");
        content.Add(new StringContent(_orgId.ToString()), "OrgId");
        var response = await client.PostAsync("/api/v1/media/upload", content);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
    }
}
