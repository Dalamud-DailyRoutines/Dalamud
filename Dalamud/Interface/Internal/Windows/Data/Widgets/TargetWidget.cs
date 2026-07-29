using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState;
using Dalamud.Game.ClientState.Objects;
using Dalamud.Interface.Utility;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying target info.
/// </summary>
internal class TargetWidget : IDataWindowWidget
{
    private bool resolveGameData;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["target"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "目标";

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
        ImGui.Checkbox("解析游戏数据"u8, ref this.resolveGameData);

        var objectTable = Service<ObjectTable>.Get();
        var targetMgr = Service<TargetManager>.Get();

        if (targetMgr.Target != null)
        {
            Util.PrintGameObject(targetMgr.Target, "当前目标", this.resolveGameData);

            ImGui.Text("目标"u8);
            Util.ShowGameObjectStruct(targetMgr.Target);

            var tot = targetMgr.Target.TargetObject;
            if (tot != null)
            {
                ImGuiHelpers.ScaledDummy(10);

                ImGui.Separator();
                ImGui.Text("目标的目标"u8);
                Util.ShowGameObjectStruct(tot);
            }

            ImGuiHelpers.ScaledDummy(10);
        }

        if (targetMgr.FocusTarget != null)
            Util.PrintGameObject(targetMgr.FocusTarget, "焦点目标", this.resolveGameData);

        if (targetMgr.MouseOverTarget != null)
            Util.PrintGameObject(targetMgr.MouseOverTarget, "鼠标悬停目标", this.resolveGameData);

        if (targetMgr.PreviousTarget != null)
            Util.PrintGameObject(targetMgr.PreviousTarget, "上一个目标", this.resolveGameData);

        if (targetMgr.SoftTarget != null)
            Util.PrintGameObject(targetMgr.SoftTarget, "软目标", this.resolveGameData);

        if (targetMgr.GPoseTarget != null)
            Util.PrintGameObject(targetMgr.GPoseTarget, "集体动作目标", this.resolveGameData);

        if (targetMgr.MouseOverNameplateTarget != null)
            Util.PrintGameObject(targetMgr.MouseOverNameplateTarget, "鼠标悬停名牌目标", this.resolveGameData);

        if (ImGui.Button("清除当前目标"u8))
            targetMgr.Target = null;

        if (ImGui.Button("清除焦点目标"u8))
            targetMgr.FocusTarget = null;

        var localPlayer = objectTable.LocalPlayer;

        if (localPlayer != null)
        {
            if (ImGui.Button("设为当前目标"u8))
                targetMgr.Target = localPlayer;

            if (ImGui.Button("设为焦点目标"u8))
                targetMgr.FocusTarget = localPlayer;
        }
        else
        {
            ImGui.Text("本地玩家为空。"u8);
        }
    }
}
