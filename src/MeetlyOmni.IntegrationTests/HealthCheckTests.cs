using System;
using System.Net.Http;
using System.Threading.Tasks;

using Xunit;

namespace MeetlyOmni.IntegrationTests;
public class BackendStatusTests
{
    [Fact]
    public async Task Backend_Is_Available()
    {
        using var httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        var baseUrl = Environment.GetEnvironmentVariable("BASE_URL") ?? LaunchSettingsReader.GetBaseUrl("http");
        var response = await httpClient.GetAsync($"{baseUrl}/swagger/index.html");

        Assert.True(response.IsSuccessStatusCode, $"Backend is not available. Status: {response.StatusCode}, Reason: {response.ReasonPhrase}");

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("swagger", content.ToLowerInvariant());
    }
}
