using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState.Fates;
using Dalamud.Interface.Textures.Internal;
using Dalamud.Interface.Utility.Raii;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying the Fate Table.
/// </summary>
internal class FateTableWidget : IDataWindowWidget
{
    private const ImGuiTableFlags TableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg |
                                               ImGuiTableFlags.Borders | ImGuiTableFlags.NoSavedSettings;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["fate", "fatetable"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "FATE 表";

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
        var fateTable = Service<FateTable>.Get();
        var textureManager = Service<TextureManager>.Get();

        if (fateTable.Length == 0)
        {
            ImGui.Text("当前没有 FATE，或数据尚未就绪。"u8);
            return;
        }

        using var table = ImRaii.Table("FateTable"u8, 13, TableFlags);
        if (!table) return;

        ImGui.TableSetupColumn("索引"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupColumn("地址"u8, ImGuiTableColumnFlags.WidthFixed, 120);
        ImGui.TableSetupColumn("FATE ID"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupColumn("状态"u8, ImGuiTableColumnFlags.WidthFixed, 80);
        ImGui.TableSetupColumn("等级"u8, ImGuiTableColumnFlags.WidthFixed, 50);
        ImGui.TableSetupColumn("图标"u8, ImGuiTableColumnFlags.WidthFixed, 30);
        ImGui.TableSetupColumn("地图图标"u8, ImGuiTableColumnFlags.WidthFixed, 30);
        ImGui.TableSetupColumn("名称"u8, ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("进度"u8, ImGuiTableColumnFlags.WidthFixed, 55);
        ImGui.TableSetupColumn("持续时间"u8, ImGuiTableColumnFlags.WidthFixed, 80);
        ImGui.TableSetupColumn("奖励"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupColumn("位置"u8, ImGuiTableColumnFlags.WidthFixed, 240);
        ImGui.TableSetupColumn("半径"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupScrollFreeze(7, 1);
        ImGui.TableHeadersRow();

        for (var i = 0; i < fateTable.Length; i++)
        {
            var fate = fateTable[i];
            if (fate == null)
                continue;

            ImGui.TableNextRow();
            ImGui.TableNextColumn(); // Index
            ImGui.Text($"#{i}");

            ImGui.TableNextColumn(); // Address
            WidgetUtil.DrawCopyableText($"0x{fate.Address:X}", "单击复制地址");

            ImGui.TableNextColumn(); // FateId
            WidgetUtil.DrawCopyableText(fate.FateId.ToString(), "单击复制 FateId（Fate 表的 RowId）");

            ImGui.TableNextColumn(); // State
            ImGui.Text(fate.State.ToString());

            ImGui.TableNextColumn(); // Level

            if (fate.Level == fate.MaxLevel)
            {
                ImGui.Text($"{fate.Level}");
            }
            else
            {
                ImGui.Text($"{fate.Level}-{fate.MaxLevel}");
            }

            ImGui.TableNextColumn(); // Icon

            if (fate.IconId != 0)
            {
                if (textureManager.Shared.GetFromGameIcon(fate.IconId).TryGetWrap(out var texture, out _))
                {
                    ImGui.Image(texture.Handle, new(ImGui.GetTextLineHeight()));

                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

                        using var tooltip = ImRaii.Tooltip();
                        ImGui.Text("单击复制 IconId"u8);
                        ImGui.Text($"ID：{fate.IconId} - 尺寸：{texture.Width}x{texture.Height}");
                        ImGui.Image(texture.Handle, new(texture.Width, texture.Height));
                    }

                    if (ImGui.IsItemClicked())
                    {
                        ImGui.SetClipboardText(fate.IconId.ToString());
                    }
                }
            }

            ImGui.TableNextColumn(); // MapIconId

            if (fate.MapIconId != 0)
            {
                if (textureManager.Shared.GetFromGameIcon(fate.MapIconId).TryGetWrap(out var texture, out _))
                {
                    ImGui.Image(texture.Handle, new(ImGui.GetTextLineHeight()));

                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

                        using var tooltip = ImRaii.Tooltip();
                        ImGui.Text("单击复制 MapIconId"u8);
                        ImGui.Text($"ID：{fate.MapIconId} - 尺寸：{texture.Width}x{texture.Height}");
                        ImGui.Image(texture.Handle, new(texture.Width, texture.Height));
                    }

                    if (ImGui.IsItemClicked())
                    {
                        ImGui.SetClipboardText(fate.MapIconId.ToString());
                    }
                }
            }

            ImGui.TableNextColumn(); // Name

            WidgetUtil.DrawCopyableText(fate.Name.ToString(), "单击复制名称");

            ImGui.TableNextColumn(); // Progress
            ImGui.Text($"{fate.Progress}%");

            ImGui.TableNextColumn(); // TimeRemaining

            if (fate.State == FateState.Running)
            {
                ImGui.Text($"{TimeSpan.FromSeconds(fate.TimeRemaining):mm\\:ss} / {TimeSpan.FromSeconds(fate.Duration):mm\\:ss}");
            }

            ImGui.TableNextColumn(); // HasExpBonus
            ImGui.Text(fate.HasBonus ? "是" : "否");

            ImGui.TableNextColumn(); // Position
            WidgetUtil.DrawCopyableText(fate.Position.ToString(), "单击复制位置");

            ImGui.TableNextColumn(); // Radius
            WidgetUtil.DrawCopyableText(fate.Radius.ToString(), "单击复制半径");
        }
    }
}
