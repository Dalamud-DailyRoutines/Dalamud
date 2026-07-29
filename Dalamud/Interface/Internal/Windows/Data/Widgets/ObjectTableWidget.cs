using System.Numerics;

using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState;
using Dalamud.Game.ClientState.Objects;
using Dalamud.Game.Gui;
using Dalamud.Game.Player;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget to display the Object Table.
/// </summary>
internal class ObjectTableWidget : IDataWindowWidget
{
    private const ImGuiWindowFlags CharacterWindowFlags = ImGuiWindowFlags.NoDecoration | ImGuiWindowFlags.AlwaysAutoResize |
                                                          ImGuiWindowFlags.NoSavedSettings | ImGuiWindowFlags.NoMove |
                                                          ImGuiWindowFlags.NoMouseInputs | ImGuiWindowFlags.NoDocking |
                                                          ImGuiWindowFlags.NoFocusOnAppearing | ImGuiWindowFlags.NoNav;

    private bool resolveGameData;
    private bool drawCharacters;
    private float maxCharaDrawDistance = 20.0f;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["ot", "objecttable"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "对象表";

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

        var chatGui = Service<ChatGui>.Get();
        var clientState = Service<ClientState>.Get();
        var playerState = Service<PlayerState>.Get();
        var gameGui = Service<GameGui>.Get();
        var objectTable = Service<ObjectTable>.Get();

        var stateString = string.Empty;

        if (objectTable.LocalPlayer == null)
        {
            ImGui.Text("本地玩家为空。"u8);
            return;
        }

        if (clientState.IsPvPExcludingDen)
        {
            ImGui.Text("PvP 期间无法访问对象表。"u8);
            return;
        }

        stateString += $"对象表长度：{objectTable.Length}\n";
        stateString += $"本地玩家名称：{playerState.CharacterName}\n";
        stateString += $"当前世界名称：{(this.resolveGameData ? playerState.CurrentWorld.ValueNullable?.Name : playerState.CurrentWorld.RowId.ToString())}\n";
        stateString += $"所属世界名称：{(this.resolveGameData ? playerState.HomeWorld.ValueNullable?.Name : playerState.HomeWorld.RowId.ToString())}\n";
        stateString += $"本地 CID：{playerState.ContentId:X}\n";
        stateString += $"上次链接的物品：{chatGui.LastLinkedItemId}\n";
        stateString += $"区域类型：{clientState.TerritoryType}\n\n";

        ImGui.Text(stateString);

        ImGui.Checkbox("在屏幕上标出角色"u8, ref this.drawCharacters);
        ImGui.SliderFloat("绘制距离"u8, ref this.maxCharaDrawDistance, 2f, 40f);

        for (var i = 0; i < objectTable.Length; i++)
        {
            var obj = objectTable[i];

            if (obj == null)
                continue;

            Util.PrintGameObject(obj, i.ToString(), this.resolveGameData);

            if (this.drawCharacters && gameGui.WorldToScreen(obj.Position, out var screenCoords))
            {
                // So, while WorldToScreen will return false if the point is off of game client screen, to
                // to avoid performance issues, we have to manually determine if creating a window would
                // produce a new viewport, and skip rendering it if so
                var objectText = $"{obj.Address:X}:{obj.GameObjectId:X}[{i}] - {obj.ObjectKind} - {obj.Name}";

                var screenPos = ImGui.GetMainViewport().Pos;
                var screenSize = ImGui.GetMainViewport().Size;

                var windowSize = ImGui.CalcTextSize(objectText);

                // Add some extra safety padding
                windowSize.X += ImGui.GetStyle().WindowPadding.X + 10;
                windowSize.Y += ImGui.GetStyle().WindowPadding.Y + 10;

                if (screenCoords.X + windowSize.X > screenPos.X + screenSize.X ||
                    screenCoords.Y + windowSize.Y > screenPos.Y + screenSize.Y)
                    continue;

                if (obj.CurrentDistance > this.maxCharaDrawDistance)
                    continue;

                ImGui.SetNextWindowPos(new Vector2(screenCoords.X, screenCoords.Y));
                ImGui.SetNextWindowBgAlpha(Math.Max(1f - (obj.CurrentDistance / this.maxCharaDrawDistance), 0.2f));

                if (ImGui.Begin($"角色 {i}##ActorWindow{i}", CharacterWindowFlags))
                    ImGui.Text(objectText);
                ImGui.End();
            }
        }
    }
}
