using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState.Conditions;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying current character condition flags.
/// </summary>
internal class ConditionWidget : IDataWindowWidget
{
    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["condition"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "状态条件";

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var condition = Service<Condition>.Get();

#if DEBUG
        ImGui.Text($"指针：{Util.DescribeAddress(condition.Address)}");
#endif

        ImGui.Text("当前状态条件："u8);
        ImGui.Separator();

        var didAny = false;

        for (var i = 0; i < Condition.MaxConditionEntries; i++)
        {
            var typedCondition = (ConditionFlag)i;
            var cond = condition[typedCondition];

            if (!cond) continue;

            didAny = true;

            ImGui.Text($"ID：{i} 枚举：{typedCondition}");
        }

        if (!didAny)
            ImGui.Text("当前没有状态条件。与商店 NPC 交谈或打开市场布告板即可查看变化。"u8);
    }

}
