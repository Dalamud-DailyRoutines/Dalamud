using System.Linq;
using System.Text.RegularExpressions;

using CheapLoc;

using Dalamud.Configuration.Internal;
using Dalamud.Game.Chat;
using Dalamud.Game.Gui;
using Dalamud.Game.Text;
using Dalamud.Game.Text.SeStringHandling;
using Dalamud.Game.Text.SeStringHandling.Payloads;
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
        chatGui.ChatMessage += this.OnChatMessage;
    }

    /// <summary>
    /// Gets the last URL seen in chat.
    /// </summary>
    public string? LastLink { get; private set; }

    [GeneratedRegex(@"(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?", RegexOptions.Compiled)]
    private static partial Regex CompiledUrlRegex();

    private void OnCheckMessageHandled(IHandleableChatMessage message)
    {
        var textVal = message.Message.TextValue;

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
        if (clientState.IsLoggedIn && clientState.TerritoryType == 0 && !this.hasSeenLoadingMsg)
        {
            this.PrintWelcomeMessage();
        }

#if !DEBUG && false
            if (!this.hasSeenLoadingMsg)
                return;
#endif

        var linkMatch = CompiledUrlRegex().Match(message.Message.TextValue);
        if (linkMatch.Value.Length > 0)
        {
            this.LastLink = linkMatch.Value;
        }
    }

    private void PrintWelcomeMessage()
    {
        var chatGui = Service<ChatGui>.GetNullable();
        var pluginManager = Service<PluginManager>.GetNullable();
        var dalamudInterface = Service<DalamudInterface>.GetNullable();
        var dalamudConfig = Service<DalamudConfiguration>.GetNullable();

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
            var linkPayload = chatGui.AddChatLinkHandler(
                (_, _) => dalamudInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.Changelogs));

            var updateMessage = new SeStringBuilder()
                .AddText("成功更新了 Dalamud。")
                .AddUiForeground(500)
                .AddText("  [")
                .Add(linkPayload)
                .AddText("更新日志")
                .Add(RawPayload.LinkTerminator)
                .AddText("]")
                .AddUiForegroundOff();

            chatGui.Print(new XivChatEntry
            {
                Message = updateMessage.Build(),
                Type = XivChatType.Notice,
            });

            this.configuration.LastVersion = Versioning.GetAssemblyVersion();
            this.configuration.QueueSave();
        }

        if (dalamudConfig?.DevMode ?? false)
        {
            var linkPayload = chatGui.AddChatLinkHandler(
                (_, _) => dalamudInterface.OpenSettingsTo(SettingsOpenKind.Experimental));

            var devModeWarningMessage = new SeStringBuilder()
                .AddText("启用了开发者模式。若非刻意为之，请及时关闭，避免蒙受损失。")
                .AddUiForeground(500)
                .AddText("  [")
                .Add(linkPayload)
                .AddText("配置")
                .Add(RawPayload.LinkTerminator)
                .AddText("]")
                .AddUiForegroundOff();

            chatGui.Print(new XivChatEntry
            {
                Message = devModeWarningMessage.Build(),
                Type = XivChatType.Notice,
            });
        }

        this.hasSeenLoadingMsg = true;
    }
}
