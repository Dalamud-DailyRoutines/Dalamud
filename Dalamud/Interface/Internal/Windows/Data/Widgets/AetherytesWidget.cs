using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState.Aetherytes;
using Dalamud.Interface.Utility.Raii;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying aetheryte table.
/// </summary>
internal class AetherytesWidget : IDataWindowWidget
{
    private const ImGuiTableFlags TableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders;

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["aetherytes"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "以太之光";

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        using var table = ImRaii.Table("##aetheryteTable"u8, 11, TableFlags);
        if (!table.Success)
            return;

        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableSetupColumn("索引"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("名称"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("ID"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("区域"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("小区"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("房屋"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("子索引"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("金币"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("优惠"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("共享房屋"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableSetupColumn("公寓"u8, ImGuiTableColumnFlags.WidthFixed);
        ImGui.TableHeadersRow();

        var tpList = Service<AetheryteList>.Get();

        for (var i = 0; i < tpList.Length; i++)
        {
            var info = tpList[i];
            if (info == null)
                continue;

            ImGui.TableNextColumn(); // Idx
            ImGui.Text($"{i}");

            ImGui.TableNextColumn(); // Name
            ImGui.Text($"{info.AetheryteData.ValueNullable?.PlaceName.ValueNullable?.Name}");

            ImGui.TableNextColumn(); // ID
            ImGui.Text($"{info.AetheryteId}");

            ImGui.TableNextColumn(); // Zone
            ImGui.Text($"{info.TerritoryId}");

            ImGui.TableNextColumn(); // Ward
            ImGui.Text($"{info.Ward}");

            ImGui.TableNextColumn(); // Plot
            ImGui.Text($"{info.Plot}");

            ImGui.TableNextColumn(); // Sub
            ImGui.Text($"{info.SubIndex}");

            ImGui.TableNextColumn(); // Gil
            ImGui.Text($"{info.GilCost}");

            ImGui.TableNextColumn(); // Favourite
            ImGui.Text(info.IsFavourite ? "是" : "否");

            ImGui.TableNextColumn(); // Shared
            ImGui.Text(info.IsSharedHouse ? "是" : "否");

            ImGui.TableNextColumn(); // Apartment
            ImGui.Text(info.IsApartment ? "是" : "否");
        }
    }
}
