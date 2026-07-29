using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState.Party;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying information about the current party.
/// </summary>
internal class PartyListWidget : IDataWindowWidget
{
    private bool resolveGameData;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["partylist", "party"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "小队列表";

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
        var partyList = Service<PartyList>.Get();

        ImGui.Checkbox("解析游戏数据"u8, ref this.resolveGameData);

        ImGui.Text($"队伍管理器：{partyList.GroupManagerAddress:X}");
        ImGui.Text($"小队列表：{partyList.GroupListAddress:X}");
        ImGui.Text($"团队列表：{partyList.AllianceListAddress:X}");

        ImGui.Text($"{partyList.Length} 名成员");

        for (var i = 0; i < partyList.Length; i++)
        {
            var member = partyList[i];
            if (member == null)
            {
                ImGui.Text($"[{i}] 为空");
                continue;
            }

            ImGui.Text($"[{i}] {member.Address:X} - {member.Name} - {member.GameObject?.GameObjectId ?? 0}");
            if (this.resolveGameData)
            {
                var actor = member.GameObject;
                if (actor == null)
                {
                    ImGui.Text("角色为空"u8);
                }
                else
                {
                    Util.PrintGameObject(actor, "-", this.resolveGameData);
                }
            }
        }
    }
}
