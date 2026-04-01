using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Dalamud.Networking.Http;
using Dalamud.Plugin.Internal.Types.Manifest;
using Dalamud.Utility;

using Newtonsoft.Json;

namespace Dalamud.Support;

/// <summary>
/// Class responsible for sending feedback.
/// </summary>
internal static class BugBait
{
    /// <summary>
    /// Send feedback to Discord.
    /// </summary>
    /// <param name="plugin">The plugin to send feedback about.</param>
    /// <param name="isTesting">Whether the plugin is a testing plugin.</param>
    /// <param name="content">The content of the feedback.</param>
    /// <param name="reporter">The reporter name.</param>
    /// <param name="includeException">Whether the most recent exception to occur should be included in the report.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task SendFeedback(IPluginManifest plugin, bool isTesting, string content, string reporter, bool includeException)
    {
        return Task.CompletedTask;
    }

    private class FeedbackModel
    {
        [JsonProperty("content")]
        public string? Content { get; set; }

        [JsonProperty("name")]
        public string? Name { get; set; }

        [JsonProperty("dhash")]
        public string? DalamudHash { get; set; }

        [JsonProperty("version")]
        public string? Version { get; set; }

        [JsonProperty("platform")]
        public string? Platform { get; set; }

        [JsonProperty("reporter")]
        public string? Reporter { get; set; }

        [JsonProperty("exception")]
        public string? Exception { get; set; }
    }
}
