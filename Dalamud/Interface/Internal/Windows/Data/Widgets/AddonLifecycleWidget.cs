using System.Diagnostics.CodeAnalysis;

using Dalamud.Bindings.ImGui;
using Dalamud.Game.Addon.Lifecycle;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Debug widget for displaying AddonLifecycle data.
/// </summary>
public class AddonLifecycleWidget : IDataWindowWidget
{
    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["AddonLifecycle"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "Addon 生命周期";

    /// <inheritdoc/>
    [MemberNotNullWhen(true, nameof(AddonLifecycle))]
    public bool Ready { get; set; }

    private AddonLifecycle? AddonLifecycle { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        Service<AddonLifecycle>
            .GetAsync()
            .ContinueWith(
                r =>
                {
                    this.AddonLifecycle = r.Result;
                    this.Ready = true;
                });
    }

    /// <inheritdoc/>
    public void Draw()
    {
        if (!this.Ready)
        {
            ImGui.Text("AddonLifecycle 引用为空，请重新加载模块。"u8);
            return;
        }

        foreach (var (eventType, addonListeners) in this.AddonLifecycle.EventListeners)
        {
            using var eventId = ImRaii.PushId(eventType.ToString());

            if (ImGui.CollapsingHeader(eventType.ToString()))
            {
                using var eventIndent = ImRaii.PushIndent();

                if (addonListeners.Count == 0)
                {
                    ImGui.Text("此事件尚未注册 Addon"u8);
                }

                foreach (var (addonName, listeners) in addonListeners)
                {
                    using var addonId = ImRaii.PushId(addonName);

                    if (ImGui.CollapsingHeader(addonName.IsNullOrEmpty() ? "全局" : addonName))
                    {
                        using var addonIndent = ImRaii.PushIndent();

                        if (listeners.Count == 0)
                        {
                            ImGui.Text("此事件尚未注册监听器"u8);
                        }

                        foreach (var listener in listeners)
                        {
                            ImGui.Text($"{listener.FunctionDelegate.Method.DeclaringType?.FullName ?? "未知声明类型"}::{listener.FunctionDelegate.Method.Name}");
                        }
                    }
                }
            }
        }
    }

}
