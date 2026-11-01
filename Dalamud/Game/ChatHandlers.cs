using System.Linq;
using System.Text.RegularExpressions;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Chat;
using Dalamud.Game.Gui;
using Dalamud.Interface;
using Dalamud.Interface.Internal;
using Dalamud.Logging.Internal;
using Dalamud.Plugin.Internal;
using Dalamud.Utility;

namespace Dalamud.Game;

/// <summary>
/// Chat events and public helper functions.
/// </summary>
[ServiceManager.EarlyLoadedService]
internal partial class ChatHandlers : IServiceType
{
    private static readonly ModuleLog Log = ModuleLog.Create<ChatHandlers>();

    [ServiceManager.ServiceDependency]
    private readonly DalamudConfiguration configuration = Service<DalamudConfiguration>.Get();

    private bool hasSeenLoadingMsg;

    [ServiceManager.ServiceConstructor]
    private ChatHandlers(ChatGui chatGui)
    {
        chatGui.CheckMessageHandled += this.OnCheckMessageHandled;
        chatGui.ChatMessage         += this.OnChatMessage;
    }

    /// <summary>
    /// Gets the last URL seen in chat.
    /// </summary>
    public string? LastLink { get; private set; }

    [GeneratedRegex(@"(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?", RegexOptions.Compiled)]
    private static partial Regex CompiledUrlRegex { get; }

    private void OnCheckMessageHandled(IHandleableChatMessage message)
    {
        var textVal = message.Message.ToString();

        if (this.configuration.BadWords != null &&
            this.configuration.BadWords.Any(x => !string.IsNullOrEmpty(x) && textVal.Contains(x)))
        {
            // This seems to be in the user block list - let's not show it
            Log.Debug("Filtered a message that contained a muted word");
            message.PreventOriginal();
            return;
        }
    }

    private void OnChatMessage(IHandleableChatMessage message)
    {
        var clientState = Service<ClientState.ClientState>.GetNullable();

        if (clientState is null)
        {
            return;
        }

        if (message.LogKind == XivChatType.Notice)
        {
            if (!this.hasSeenLoadingMsg)
            {
                this.PrintWelcomeMessage();
            }
        }

        // For injections while logged in
        if (clientState.IsLoggedIn && clientState.TerritoryType.RowId == 0 && !this.hasSeenLoadingMsg)
        {
            this.PrintWelcomeMessage();
        }

#if !DEBUG && false
            if (!this.hasSeenLoadingMsg)
                return;
#endif

        var linkMatch = CompiledUrlRegex.Match(message.Message.ToString());

        if (linkMatch.Value.Length > 0)
        {
            this.LastLink = linkMatch.Value;
        }
    }

    private void PrintWelcomeMessage()
    {
        var chatGui          = Service<ChatGui>.GetNullable();
        var pluginManager    = Service<PluginManager>.GetNullable();
        var dalamudInterface = Service<DalamudInterface>.GetNullable();
        var dalamudConfig    = Service<DalamudConfiguration>.GetNullable();

        if (chatGui is null || pluginManager is null || dalamudInterface is null)
        {
            return;
        }

        if (this.configuration.PrintDalamudWelcomeMsg)
            chatGui.Print($"欢迎使用 Dalamud {Versioning.GetScmVersion()}，当前加载了{pluginManager.InstalledPlugins.Count(x => x.IsLoaded)}个插件。");

        if (this.configuration.PrintPluginsWelcomeMsg)
        {
            foreach (var plugin in pluginManager.InstalledPlugins.OrderBy(plugin => plugin.Name).Where(x => x.IsLoaded))
                chatGui.Print($"  \ue06f {plugin.Name}（版本{plugin.EffectiveVersion}）");
        }

        if (string.IsNullOrEmpty(this.configuration.LastVersion) || !Versioning.GetAssemblyVersion().StartsWith(this.configuration.LastVersion))
        {
            var dalamudLinkPayload = chatGui.AddChatLinkHandler(_ => dalamudInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.Changelogs));

            using var rssb = new RentedSeStringBuilder();

            chatGui.Print
            (
                new PrintableChatMessage
                {
                    LogKind = XivChatType.Notice,
                    Message = rssb.Builder
                                  .Append("成功更新了 Dalamud。")
                                  .PushColorType(500)
                                  .Append("  [ ")
                                  .PushDalamudLink(dalamudLinkPayload)
                                  .Append("更新日志")
                                  .PopLink()
                                  .Append(" ]")
                                  .PopColorType()
                                  .ToReadOnlySeString()
                }
            );

            this.configuration.LastVersion = Versioning.GetAssemblyVersion();
            this.configuration.QueueSave();
        }

        if (dalamudConfig?.DevMode ?? false)
        {
            var linkPayload = chatGui.AddChatLinkHandler(_ => dalamudInterface.OpenSettingsTo(SettingsOpenKind.Experimental));

            using var rssb = new RentedSeStringBuilder();

            chatGui.Print
            (
                new PrintableChatMessage
                {
                    LogKind = XivChatType.Notice,
                    Message = rssb.Builder
                                  .Append("启用了开发者模式。若非刻意为之，请及时关闭，避免蒙受损失。")
                                  .PushColorType(500)
                                  .Append("  [ ")
                                  .PushDalamudLink(linkPayload)
                                  .Append("配置")
                                  .PopLink()
                                  .Append(" ]")
                                  .PopColorType()
                                  .ToReadOnlySeString()
                }
            );
        }

        this.hasSeenLoadingMsg = true;
    }
}
