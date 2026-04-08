using System.Diagnostics.CodeAnalysis;

using CheapLoc;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Internal.ReShadeHandling;
using Dalamud.Interface.Internal.Windows.Settings.Widgets;

namespace Dalamud.Interface.Internal.Windows.Settings.Tabs;

[SuppressMessage(
    "StyleCop.CSharp.DocumentationRules",
    "SA1600:Elements should be documented",
    Justification = "Internals")]
internal sealed class SettingsTabExperimental : SettingsTab
{
    public override string Title => Loc.Localize("DalamudSettingsExperimental", "Experimental");

    public override SettingsOpenKind Kind => SettingsOpenKind.Experimental;

    public override SettingsEntry[] Entries { get; } =
    [
        new SettingsEntry<float>(
            Loc.Localize("DalamudSettingBackgroundBlur", "窗口毛玻璃效果强度系数"),
            Loc.Localize("DalamudSettingBackgroundBlurHint", "控制插件窗口背景的毛玻璃效果强度。设置为 0 以禁用。\n本效果需要各插件主动适配。"),
            c => c.PluginUiBackgroundBlurStrength,
            (v, c) => c.PluginUiBackgroundBlurStrength = v)
        {
            CustomDraw = static e =>
            {
                ImGui.TextWrapped(e.Name!);

                var v = e.Value;
                if (ImGui.SliderFloat($"###{e}", ref v, 0f, 10f, "%.1f%%"))
                    e.Value = v;
            },
        },

        new GapSettingsEntry(5, true),
        
        new EnumSettingsEntry<ReShadeHandlingMode>(
            Loc.Localize("DalamudSettingsReShadeHandlingMode", "ReShade 处理模式"),
            Loc.Localize(
                "DalamudSettingsReShadeHandlingModeHint",
                "当你遇到与 ReShade 相关的问题时，可以选择以下不同选项来尝试解决问题\n注：所有选项需重启游戏后生效"),
            c => c.ReShadeHandlingMode,
            (v, c) => c.ReShadeHandlingMode = v,
            fallbackValue: ReShadeHandlingMode.Default,
            warning: static rshm =>
            {
                var warning = string.Empty;
                warning += rshm is ReShadeHandlingMode.UnwrapReShade or ReShadeHandlingMode.None ||
                           Service<DalamudConfiguration>.Get().SwapChainHookMode == SwapChainHelper.HookMode.ByteCode
                               ? string.Empty
                               : "当前选项将被忽略且不会执行特殊 ReShade 处理，因为已启用 SwapChain vtable Hook 模式。";

                if (ReShadeAddonInterface.ReShadeIsSignedByReShade)
                {
                    warning += warning.Length > 0 ? "\n" : string.Empty;
                    warning += Loc.Localize(
                        "ReShadeNoAddonSupportNotificationContent",
                        "你安装的 ReShade 版本不支持完整 Addon 功能，可能与 Dalamud 或游戏存在兼容性问题\n" +
                        "请下载并安装支持完整 Addon 功能的 ReShade 版本");
                }

                return warning.Length > 0 ? warning : null;
            })
        {
            FriendlyEnumNameGetter = x => x switch
            {
                ReShadeHandlingMode.Default                           => "默认模式",
                ReShadeHandlingMode.UnwrapReShade                     => "解包模式",
                ReShadeHandlingMode.ReShadeAddonPresent               => "ReShade Addon（当前状态）",
                ReShadeHandlingMode.ReShadeAddonReShadeOverlay        => "ReShade Addon（reshade_overlay）",
                ReShadeHandlingMode.HookReShadeDxgiSwapChainOnPresent => "Hook ReShade::DXGISwapChain::OnPresent",
                ReShadeHandlingMode.None                              => "不处理",
                _                                                     => "<无效值>",
            },
        },
    ];
}
