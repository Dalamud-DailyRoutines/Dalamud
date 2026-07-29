using Dalamud.Bindings.ImGui;
using Dalamud.Game.Gui;
using Dalamud.Game.NativeWrapper;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying Addon Data.
/// </summary>
internal class AddonWidget : IDataWindowWidget
{
    private string inputAddonName = string.Empty;
    private int inputAddonIndex;
    private AgentInterfacePtr agentInterfacePtr;

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "Addon 信息";

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; }

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var gameGui = Service<GameGui>.Get();

        ImGui.InputText("Addon 名称"u8, ref this.inputAddonName, 256);
        ImGui.InputInt("Addon 索引"u8, ref this.inputAddonIndex);

        if (this.inputAddonName.IsNullOrEmpty())
            return;

        var addon = gameGui.GetAddonByName(this.inputAddonName, this.inputAddonIndex);
        if (addon.IsNull)
        {
            ImGui.Text("空"u8);
            return;
        }

        ImGui.Text($"{addon.Name} - {Util.DescribeAddress(addon)}\n    可见：{(addon.IsVisible ? "是" : "否")} x：{addon.X} y：{addon.Y} 缩放：{addon.Scale}，宽：{addon.Width}，高：{addon.Height}");

        if (ImGui.Button("查找 Agent"u8))
        {
            this.agentInterfacePtr = gameGui.FindAgentInterface(addon);
        }

        if (!this.agentInterfacePtr.IsNull)
        {
            ImGui.Text($"Agent：{Util.DescribeAddress(this.agentInterfacePtr)}");
            ImGui.SameLine();

            if (ImGui.Button("复制"u8))
                ImGui.SetClipboardText(this.agentInterfacePtr.Address.ToString("X"));
        }
    }
}
