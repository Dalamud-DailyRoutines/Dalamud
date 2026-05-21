using System.Diagnostics.CodeAnalysis;

using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Text;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Internal.Windows.Settings.Widgets;
using Dalamud.Interface.Utility;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Utility.Internal;

namespace Dalamud.Interface.Internal.Windows.Settings.Tabs;

[SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:Elements should be documented", Justification = "Internals")]
internal sealed class SettingsTabGeneral : SettingsTab
{
    public override string Title => "常规";

    public override SettingsOpenKind Kind => SettingsOpenKind.General;

    public override SettingsEntry[] Entries { get; } =
    [
        new LanguageChooserSettingsEntry(),

        new GapSettingsEntry(5),

        new EnumSettingsEntry<XivChatType>(
            "Dalamud 聊天频道",
            "选择用于 Dalamud 常规消息的聊天频道",
            c => c.GeneralChatType,
            (v, c) => c.GeneralChatType = v,
            warning: v =>
            {
                // TODO: Maybe actually implement UI for the validity check...
                if (v == XivChatType.None)
                    return "请勿选择 \"None\"";

                return null;
            },
            fallbackValue: XivChatType.Debug),

        new GapSettingsEntry(5),

        new SettingsEntry<bool>(
            "游戏加载前等待插件",
            "在插件加载完成前阻止游戏继续加载",
            c => c.IsResumeGameAfterPluginLoad,
            (v, c) => c.IsResumeGameAfterPluginLoad = v),

        new SettingsEntry<bool>(
            "匹配副本成功时, 使游戏任务栏图标闪烁",
            "匹配副本成功时, 在任务栏闪烁游戏窗口图标以提醒",
            c => c.DutyFinderTaskbarFlash,
            (v, c) => c.DutyFinderTaskbarFlash = v),

        new SettingsEntry<bool>(
            "进入副本时, 发送聊天栏消息",
            "进入副本时, 发送一条聊天消息说明当前进入的副本",
            c => c.DutyFinderChatMessage,
            (v, c) => c.DutyFinderChatMessage = v),

        new SettingsEntry<bool>(
            "发送 Dalamud 欢迎消息",
            "登录时, 发送一条来自 Dalamud 的登录欢迎消息",
            c => c.PrintDalamudWelcomeMsg,
            (v, c) => c.PrintDalamudWelcomeMsg = v),

        new SettingsEntry<bool>(
            "在欢迎消息中显示已加载插件",
            "登录时, 发送一条聊天消息, 列出已加载的插件",
            c => c.PrintPluginsWelcomeMsg,
            (v, c) => c.PrintPluginsWelcomeMsg = v),

        new SettingsEntry<bool>(
            "在系统菜单中添加 Dalamud 条目",
            "在系统菜单中添加用于打开 Dalamud 插件和设置的条目",
            c => c.DoButtonsSystemMenu,
            (v, c) => c.DoButtonsSystemMenu = v),

        new GapSettingsEntry(5),

        new SettingsEntry<bool>(
            "匿名上传市场数据",
            "浏览市场时匿名向 Universalis 提供游戏内市场板数据, 数据无法关联到个人",
            c => c.IsMbCollect,
            (v, c) => c.IsMbCollect = v),

        new GapSettingsEntry(5),
    ];
}
