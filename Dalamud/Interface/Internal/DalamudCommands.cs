using System.Diagnostics;
using System.IO;
using System.Linq;
using Dalamud.Configuration.Internal;
using Dalamud.Game;
using Dalamud.Game.Command;
using Dalamud.Game.Gui;
using Dalamud.Plugin.Internal;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal;

/// <summary>
/// Class handling Dalamud core commands.
/// </summary>
[ServiceManager.EarlyLoadedService]
internal class DalamudCommands : IServiceType
{
    [ServiceManager.ServiceConstructor]
    private DalamudCommands(CommandManager commandManager)
    {
        commandManager.AddHandler
        (
            "/xldclose",
            new CommandInfo(OnUnloadCommand)
            {
                HelpMessage = "卸载 XIVLauncher 游戏内插件框架，仅供调试使用。",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xlkill",
            new CommandInfo(OnKillCommand)
            {
                HelpMessage = "Kill the game. For debug use only!",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xlrestart",
            new CommandInfo(OnRestartCommand)
            {
                HelpMessage = "Restart the game. For debug use only!",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xlhelp",
            new CommandInfo(OnHelpCommand)
            {
                HelpMessage = "显示可用命令列表。提供参数时，显示对应命令的帮助。"
            }
        );

        commandManager.AddHandler
        (
            "/xlmute",
            new CommandInfo(OnBadWordsAddCommand)
            {
                HelpMessage = "屏蔽聊天中的词语或句子。用法：/xlmute <词语或句子>",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xlmutelist",
            new CommandInfo(OnBadWordsListCommand)
            {
                HelpMessage = "列出已屏蔽的词语或句子。"
            }
        );

        commandManager.AddHandler
        (
            "/xlunmute",
            new CommandInfo(OnBadWordsRemoveCommand)
            {
                HelpMessage = "取消屏蔽词语或句子。用法：/xlunmute <词语或句子>"
            }
        );

        commandManager.AddHandler
        (
            "/ll",
            new CommandInfo(OnLastLinkCommand)
            {
                HelpMessage = "使用默认浏览器打开聊天中最后出现的链接。"
            }
        );

        commandManager.AddHandler
        (
            "/xlbgmset",
            new CommandInfo(OnBgmSetCommand)
            {
                HelpMessage = "设置游戏背景音乐。用法：/xlbgmset <BGM ID>"
            }
        );

        commandManager.AddHandler
        (
            "/xldev",
            new CommandInfo(OnDebugDrawDevMenu)
            {
                HelpMessage = "显示开发者菜单。",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xlstats",
            new CommandInfo(OnTogglePluginStats)
            {
                HelpMessage = "打开插件统计窗口。"
            }
        );

        commandManager.AddHandler
        (
            "/xldata",
            new CommandInfo(OnDebugDrawDataMenu)
            {
                HelpMessage = "打开开发者数据窗口。用法：/xldata [数据类别]",
                ShowInHelp  = false
            }
        );

        commandManager.AddHandler
        (
            "/xllog",
            new CommandInfo(OnOpenLog)
            {
                HelpMessage = "打开插件日志窗口或控制台。"
            }
        );

        commandManager.AddHandler
        (
            "/xlplugins",
            new CommandInfo(OnOpenInstallerCommand)
            {
                HelpMessage = "打开插件安装器"
            }
        );

        commandManager.AddHandler
        (
            "/xllanguage",
            new CommandInfo(OnSetLanguageCommand)
            {
                HelpMessage =
                    "设置 Dalamud 及支持此功能的插件的语言。可用语言：" +
                    Localization.ApplicableLangCodes.Aggregate("en", (current, code) => current + ", " + code)
            }
        );

        commandManager.AddHandler
        (
            "/xlsettings",
            new CommandInfo(OnOpenSettingsCommand)
            {
                HelpMessage = "打开 Dalamud 设置。"
            }
        );

        commandManager.AddHandler
        (
            "/xlversion",
            new CommandInfo(OnVersionInfoCommand)
            {
                HelpMessage = "Dalamud version info"
            }
        );

        commandManager.AddHandler
        (
            "/xlui",
            new CommandInfo(OnUiCommand)
            {
                HelpMessage = "切换 Dalamud 界面的显示模式。部分插件对游戏原生界面的修改也可能受到影响。"
            }
        );

        commandManager.AddHandler
        (
            "/xlprofiler",
            new CommandInfo(OnOpenProfilerCommand)
            {
                HelpMessage = "打开 Dalamud 启动耗时分析器。"
            }
        );

        commandManager.AddHandler
        (
            "/xlcopylog",
            new CommandInfo(OnCopyLogCommand)
            {
                HelpMessage = "将 dalamud.log 文件复制到剪贴板。"
            }
        );
        // Add the new command handler for toggling multi-monitor option
        commandManager.AddHandler
        (
            "/xltogglemultimonitor",
            new CommandInfo(OnToggleMultiMonitorCommand)
            {
                HelpMessage = "切换多显示器窗口功能。"
            }
        );
    }

    private static void OnUnloadCommand(string command, string arguments)
    {
        Service<ChatGui>.Get().Print("Unloading...");
        Service<Framework>.Get().UnloadDalamud();
    }

    private static void OnKillCommand(string command, string arguments)
    {
        Process.GetCurrentProcess().Kill();
    }

    private static void OnRestartCommand(string command, string arguments)
    {
        Dalamud.RestartGame();
    }

    private static void OnHelpCommand(string command, string arguments)
    {
        var chatGui        = Service<ChatGui>.Get();
        var commandManager = Service<CommandManager>.Get();

        if (arguments.IsNullOrWhitespace())
        {
            chatGui.Print("可用命令：");

            foreach (var cmd in commandManager.Commands.OrderBy(cInfo => cInfo.Key))
            {
                if (!cmd.Value.ShowInHelp)
                    continue;

                chatGui.Print($"{cmd.Key}: {cmd.Value.HelpMessage}");
            }
        }
        else
        {
            var trimmedArguments = arguments.Trim();
            var targetCommandText = trimmedArguments[0] == '/' ?
                                        trimmedArguments :
                                        $"/{trimmedArguments}";
            chatGui.Print
            (
                commandManager.Commands.TryGetValue(targetCommandText, out var targetCommand) ?
                    $"{targetCommandText}: {targetCommand.HelpMessage}" :
                    "未找到命令。"
            );
        }
    }

    private static void OnBadWordsAddCommand(string command, string arguments)
    {
        var chatGui = Service<ChatGui>.Get();

        chatGui.PrintError("Dalamud 内置的聊天屏蔽词功能已弃用，无法添加新的屏蔽词。请使用插件实现此功能。");
    }

    private static void OnBadWordsListCommand(string command, string arguments)
    {
        var chatGui       = Service<ChatGui>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        configuration.BadWords ??= [];

        if (configuration.BadWords.Count == 0)
        {
            chatGui.Print("没有已屏蔽的词语或句子。");
            return;
        }

        configuration.QueueSave();

        foreach (var word in configuration.BadWords)
            chatGui.Print($"\"{word}\"");
    }

    private static void OnBadWordsRemoveCommand(string command, string arguments)
    {
        var chatGui       = Service<ChatGui>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        configuration.BadWords ??= [];

        configuration.BadWords.RemoveAll(x => x == arguments);

        configuration.QueueSave();

        chatGui.Print($"已取消屏蔽“{arguments}”。");
    }

    private static void OnLastLinkCommand(string command, string arguments)
    {
        var chatHandlers = Service<ChatHandlers>.Get();
        var chatGui      = Service<ChatGui>.Get();

        if (string.IsNullOrEmpty(chatHandlers.LastLink))
        {
            chatGui.Print("尚未发现链接。");
            return;
        }

        chatGui.Print($"正在打开 {chatHandlers.LastLink}");
        Process.Start
        (
            new ProcessStartInfo(chatHandlers.LastLink)
            {
                UseShellExecute = true
            }
        );
    }

    private static void OnBgmSetCommand(string command, string arguments)
    {
        var gameGui = Service<GameGui>.Get();

        if (ushort.TryParse(arguments, out var value))
        {
            gameGui.SetBgm(value);
        }
        else
        {
            // Revert to the original BGM by specifying an invalid one
            gameGui.ResetBgm();
        }
    }

    private static void OnDebugDrawDevMenu(string command, string arguments)
    {
        Service<DalamudInterface>.Get().ToggleDevMenu();
        Service<DalamudConfiguration>.Get().DevMode = true;
    }

    private static void OnTogglePluginStats(string command, string arguments)
    {
        Service<DalamudInterface>.Get().TogglePluginStatsWindow();
    }

    private static void OnDebugDrawDataMenu(string command, string arguments)
    {
        var dalamudInterface = Service<DalamudInterface>.Get();

        if (string.IsNullOrEmpty(arguments))
            dalamudInterface.ToggleDataWindow();
        else
            dalamudInterface.ToggleDataWindow(arguments);
    }

    private static void OnOpenLog(string command, string arguments)
    {
        Service<DalamudInterface>.Get().ToggleLogWindow();
    }

    private static void OnVersionInfoCommand(string command, string arguments)
    {
        var       chatGui = Service<ChatGui>.Get();
        using var rssb    = new RentedSeStringBuilder();

        chatGui.Print
        (
            rssb.Builder
                .AppendSetItalic(true)
                .Append("Dalamud:")
                .AppendSetItalic(false)
                .Append($" {Versioning.GetScmVersion()}")
                .ToReadOnlySeString()
        );

        chatGui.Print
        (
            rssb.Builder
                .Clear()
                .AppendSetItalic(true)
                .Append("FFXIVCS:")
                .AppendSetItalic(false)
                .Append($" {Versioning.GetGitHashClientStructs()}")
                .ToReadOnlySeString()
        );
    }

    private static void OnOpenInstallerCommand(string command, string arguments)
    {
        var configuration = Service<DalamudConfiguration>.Get();
        Service<DalamudInterface>.Get().TogglePluginInstallerWindowTo(configuration.PluginInstallerOpen);
    }

    private static void OnSetLanguageCommand(string command, string arguments)
    {
        var chatGui       = Service<ChatGui>.Get();
        var configuration = Service<DalamudConfiguration>.Get();
        var localization  = Service<Localization>.Get();

        if (Localization.ApplicableLangCodes.Contains(arguments.ToLowerInvariant()) || arguments.Equals("en", StringComparison.InvariantCultureIgnoreCase))
        {
            localization.SetupWithLangCode(arguments.ToLowerInvariant());
            configuration.LanguageOverride = arguments.ToLowerInvariant();

            chatGui.Print($"语言已设置为 {arguments}");
        }
        else
        {
            localization.SetupWithUiCulture();
            configuration.LanguageOverride = null;

            chatGui.Print("语言已设置为 default");
        }

        configuration.QueueSave();
    }

    private static void OnOpenSettingsCommand(string command, string arguments)
    {
        Service<DalamudInterface>.Get().ToggleSettingsWindow();
    }

    private static void OnUiCommand(string command, string arguments)
    {
        var im = Service<InterfaceManager>.Get();

        im.IsDispatchingEvents = arguments switch
        {
            "show" => true,
            "hide" => false,
            _      => !im.IsDispatchingEvents
        };

        var pm = Service<PluginManager>.Get();

        foreach (var plugin in pm.InstalledPlugins)
        {
            if (im.IsDispatchingEvents)
            {
                plugin.DalamudInterface?.LocalUiBuilder.NotifyShowUi();
            }
            else
            {
                plugin.DalamudInterface?.LocalUiBuilder.NotifyHideUi();
            }
        }
    }

    private static void OnOpenProfilerCommand(string command, string arguments)
    {
        Service<DalamudInterface>.Get().ToggleProfilerWindow();
    }

    private static void OnCopyLogCommand(string command, string arguments)
    {
        var chatGui = Service<ChatGui>.Get();
        var logPath = Path.Join
        (
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "XIVLauncherCN",
            "dalamud.log"
        );
        var message = Util.CopyFilesToClipboard([logPath]) ?
                          "已将日志文件复制到剪贴板。" :
                          "无法将日志文件复制到剪贴板。";
        chatGui.Print(message);
    }

    private static void OnToggleMultiMonitorCommand(string command, string arguments)
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var chatGui       = Service<ChatGui>.Get();

        configuration.IsDisableViewport = !configuration.IsDisableViewport;
        configuration.QueueSave();

        var message = configuration.IsDisableViewport ?
                          "已禁用多显示器窗口。" :
                          "已启用多显示器窗口。";

        chatGui.Print(message);
    }
}
