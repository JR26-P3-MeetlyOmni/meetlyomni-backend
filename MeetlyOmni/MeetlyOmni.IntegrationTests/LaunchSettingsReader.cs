using System.Text.Json.Nodes;

using Newtonsoft.Json;

namespace MeetlyOmni.IntegrationTests;

public static class LaunchSettingsReader
{
    public static string GetBaseUrl(string profileName = "https")
    {
        if (string.IsNullOrWhiteSpace(profileName))
            throw new ArgumentException("Profile name cannot be null or empty", nameof(profileName));
        // Adjust path to point to your API project relative to the test project
        var apiProjectPath = Environment.GetEnvironmentVariable("API_PROJECT_PATH") ??
            FindApiProjectPath() ??
            throw new InvalidOperationException("Unable to locate MeetlyOmni.Api project. Set API_PROJECT_PATH environment variable.");
        //Path.Combine(AppContext.BaseDirectory, "../../../../MeetlyOmni.Api");
        var pathToLaunchSettings = Path.Combine(apiProjectPath, "Properties", "launchSettings.json");

        if (!File.Exists(pathToLaunchSettings))
            throw new FileNotFoundException("launchSettings.json not found", pathToLaunchSettings);

        var json = File.ReadAllText(pathToLaunchSettings);
        JsonNode? root;

        try
        {
            root = JsonNode.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Failed to parse launchSettings.json", ex);
        }

        var profiles = root?["profiles"]?.AsObject();
        if (profiles == null || !profiles.ContainsKey(profileName))
            throw new InvalidOperationException($"Profile '{profileName}' not found in launchSettings.json");

        var appUrls = profiles[profileName]?["applicationUrl"]?.ToString();
        if (string.IsNullOrEmpty(appUrls))
            throw new InvalidOperationException("applicationUrl is missing");

        // Return the first URL (https preferred)
        var urls = appUrls.Split(';', StringSplitOptions.RemoveEmptyEntries)
                            .Select(u => u.Trim())
                            .Where(u => !string.IsNullOrEmpty(u))
                            .ToArray();

        if (!urls.Any())
            throw new InvalidOperationException("No valid URLs found in applicationUrl");

        return urls.FirstOrDefault(u => u.StartsWith("https", StringComparison.OrdinalIgnoreCase)) ?? urls.First();
    }

    private static string? FindApiProjectPath()
    {
        var currentDir = new DirectoryInfo(AppContext.BaseDirectory);
        while (currentDir != null)
        {
            var apiProjectDir = Path.Combine(currentDir.FullName, "MeetlyOmni.Api");
            if (Directory.Exists(apiProjectDir))
                return apiProjectDir;
            currentDir = currentDir.Parent;
        }
        return null;
    }
}
