using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

using MeetlyOmni.Api;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;

using Xunit;

namespace MeetlyOmni.IntegrationTests.Controllers;

public class MediaControllerReuploadIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public MediaControllerReuploadIntegrationTests(WebApplicationFactory<Program> factory)
    {
        var configuredFactory = factory.WithWebHostBuilder(builder =>
        {
            // assume the API project is in a sibling directory named "MeetlyOmni.Api"
            builder.UseContentRoot(Path.Combine(Directory.GetCurrentDirectory(), "../MeetlyOmni.Api"));
        });

        // ?? BaseAddress??? Invalid request URI
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });
    }

    [Fact]
    public async Task Reupload_Returns_200_And_Metadata_On_Valid_Request()
    {
        var orgId = Guid.NewGuid();
        var key = $"test/{orgId}/covers/2025/09/22/test_cover.png";

        var content = new MultipartFormDataContent();
        var imageBytes = new byte[1024];
        content.Add(new ByteArrayContent(imageBytes)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("image/png") }
        }, "file", "cover.png");
        content.Add(new StringContent(key), "key");
        content.Add(new StringContent(orgId.ToString()), "orgId");

        var response = await _client.PutAsync("/api/v1/media/reupload", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"key\"", json);
        Assert.Contains("\"url\"", json);
    }

    [Fact]
    public async Task Reupload_Returns_401_If_Unauthenticated()
    {
        var orgId = Guid.NewGuid();
        var key = $"test/{orgId}/covers/2025/09/22/test_cover.png";

        var content = new MultipartFormDataContent();
        var imageBytes = new byte[1024];
        content.Add(new ByteArrayContent(imageBytes)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("image/png") }
        }, "file", "cover.png");
        content.Add(new StringContent(key), "key");
        content.Add(new StringContent(orgId.ToString()), "orgId");

        // ??? Authorization
        var response = await _client.PutAsync("/api/v1/media/reupload", content);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Reupload_Returns_400_If_File_Missing()
    {
        var orgId = Guid.NewGuid();
        var key = $"test/{orgId}/covers/2025/09/22/test_cover.png";

        var content = new MultipartFormDataContent();
        content.Add(new StringContent(key), "key");
        content.Add(new StringContent(orgId.ToString()), "orgId");

        var response = await _client.PutAsync("/api/v1/media/reupload", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Reupload_Returns_413_If_File_Too_Large()
    {
        var orgId = Guid.NewGuid();
        var key = $"test/{orgId}/covers/2025/09/22/test_cover.png";

        var content = new MultipartFormDataContent();
        var imageBytes = new byte[6 * 1024 * 1024]; // 6MB
        content.Add(new ByteArrayContent(imageBytes)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("image/png") }
        }, "file", "cover.png");
        content.Add(new StringContent(key), "key");
        content.Add(new StringContent(orgId.ToString()), "orgId");

        var response = await _client.PutAsync("/api/v1/media/reupload", content);
        Assert.Equal((HttpStatusCode)413, response.StatusCode);
    }

    [Fact]
    public async Task Reupload_Returns_415_If_Invalid_MimeType()
    {
        var orgId = Guid.NewGuid();
        var key = $"test/{orgId}/covers/2025/09/22/test_cover.png";

        var content = new MultipartFormDataContent();
        var imageBytes = new byte[1024];
        content.Add(new ByteArrayContent(imageBytes)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/pdf") }
        }, "file", "cover.pdf");
        content.Add(new StringContent(key), "key");
        content.Add(new StringContent(orgId.ToString()), "orgId");

        var response = await _client.PutAsync("/api/v1/media/reupload", content);
        Assert.Equal((HttpStatusCode)415, response.StatusCode);
    }
}

