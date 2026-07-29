using System.Buffers.Binary;
using System.Numerics;
using System.Text;

using Dalamud.Bindings.ImGui;
using Dalamud.Data;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.ImGuiSeStringRenderer.Internal;
using Dalamud.Interface.Utility.Raii;

using Lumina.Excel.Sheets;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying all UI Colors from Lumina.
/// </summary>
internal class UiColorWidget : IDataWindowWidget
{
    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["uicolor"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "界面颜色";

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
        var colors = Service<DataManager>.GetNullable()?.GetExcelSheet<UIColor>()
            ?? throw new InvalidOperationException("UIColor 表尚未加载。");

        Service<SeStringRenderer>.Get().CompileAndDrawWrapped(
            "· 颜色以 #" +
            "<edgecolor(0xFFEEEE)><color(0xFF0000)>RR<color(stackcolor)><edgecolor(stackcolor)>" +
            "<edgecolor(0xEEFFEE)><color(0x00FF00)>GG<color(stackcolor)><edgecolor(stackcolor)>" +
            "<edgecolor(0xEEEEFF)><color(0x0000FF)>BB<color(stackcolor)><edgecolor(stackcolor)> 形式表示。<br>" +
            "· 单击颜色可复制颜色代码。<br>" +
            "· 与后一种颜色搭配使用时，将鼠标悬停在颜色上可预览带描边的文本。");

        using var table = ImRaii.Table("UIColor"u8, 9);
        if (!table.Success)
            return;

        ImGui.TableSetupScrollFreeze(0, 1);
        var rowidw = ImGui.CalcTextSize("9999999"u8).X;
        var colorw = ImGui.CalcTextSize("#999999"u8).X;
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#AAAAAA"u8).X);
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#BBBBBB"u8).X);
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#CCCCCC"u8).X);
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#DDDDDD"u8).X);
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#EEEEEE"u8).X);
        colorw = Math.Max(colorw, ImGui.CalcTextSize("#FFFFFF"u8).X);
        colorw += ImGui.GetFrameHeight() + ImGui.GetStyle().FramePadding.X;
        ImGui.TableSetupColumn("行 ID"u8, ImGuiTableColumnFlags.WidthFixed, rowidw);
        ImGui.TableSetupColumn("深色"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("浅色"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("经典 FF"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("透明蓝"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("透明白"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("透明绿"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("透明灰"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableSetupColumn("透明粉"u8, ImGuiTableColumnFlags.WidthFixed, colorw);
        ImGui.TableHeadersRow();

        var clipper = ImGui.ImGuiListClipper();
        clipper.Begin(colors.Count, ImGui.GetFrameHeightWithSpacing());
        while (clipper.Step())
        {
            for (var i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
            {
                var row = colors.GetRowAt(i);
                UIColor? adjacentRow = null;
                if (i + 1 < colors.Count)
                {
                    var adjRow = colors.GetRowAt(i + 1);
                    if (adjRow.RowId == row.RowId + 1)
                    {
                        adjacentRow = adjRow;
                    }
                }

                var id = row.RowId;

                ImGui.TableNextRow();

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                ImGui.Text($"{id}");

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_dark"))
                {
                    if (this.DrawColorColumn(row.Dark) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.Dark, adjacentRow.Value.Dark);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_light"))
                {
                    if (this.DrawColorColumn(row.Light) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.Light, adjacentRow.Value.Light);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_classic"))
                {
                    if (this.DrawColorColumn(row.ClassicFF) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.ClassicFF, adjacentRow.Value.ClassicFF);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_blue"))
                {
                    if (this.DrawColorColumn(row.ClearBlue) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.ClearBlue, adjacentRow.Value.ClearBlue);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_white"))
                {
                    if (this.DrawColorColumn(row.ClearWhite) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.ClearWhite, adjacentRow.Value.ClearWhite);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_green"))
                {
                    if (this.DrawColorColumn(row.ClearGreen) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.ClearGreen, adjacentRow.Value.ClearGreen);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_grey"))
                {
                    if (this.DrawColorColumn(row.Unknown2) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.Unknown2, adjacentRow.Value.Unknown2);
                }

                ImGui.TableNextColumn();
                ImGui.AlignTextToFramePadding();
                using (ImRaii.PushId($"row{id}_pink"))
                {
                    if (this.DrawColorColumn(row.Unknown3) && adjacentRow.HasValue)
                        DrawEdgePreview(id, row.Unknown3, adjacentRow.Value.Unknown3);
                }
            }
        }

        clipper.Destroy();
    }

    private static void DrawEdgePreview(uint id, uint sheetColor, uint sheetColor2)
    {
        using var tooltip = ImRaii.Tooltip();

        Span<byte> buf = stackalloc byte[256];
        var ptr = 0;
        ptr += Encoding.UTF8.GetBytes("<colortype(", buf[ptr..]);
        id.TryFormat(buf[ptr..], out var bytesWritten);
        ptr += bytesWritten;
        ptr += Encoding.UTF8.GetBytes(")><edgecolortype(", buf[ptr..]);
        (id + 1).TryFormat(buf[ptr..], out bytesWritten);
        ptr += bytesWritten;
        ptr += Encoding.UTF8.GetBytes(")>", buf[ptr..]);
        Service<SeStringRenderer>.Get().Draw(
            buf[..ptr],
            new()
            {
                Edge = true,
                Color = BinaryPrimitives.ReverseEndianness(sheetColor) | 0xFF000000u,
                EdgeColor = BinaryPrimitives.ReverseEndianness(sheetColor2) | 0xFF000000u,
                WrapWidth = float.PositiveInfinity,
            });

        ptr = 0;
        ptr += Encoding.UTF8.GetBytes("<colortype(", buf[ptr..]);
        (id + 1).TryFormat(buf[ptr..], out bytesWritten);
        ptr += bytesWritten;
        ptr += Encoding.UTF8.GetBytes(")><edgecolortype(", buf[ptr..]);
        id.TryFormat(buf[ptr..], out bytesWritten);
        ptr += bytesWritten;
        ptr += Encoding.UTF8.GetBytes(")>", buf[ptr..]);
        Service<SeStringRenderer>.Get().Draw(
            buf[..ptr],
            new()
            {
                Edge = true,
                Color = BinaryPrimitives.ReverseEndianness(sheetColor2) | 0xFF000000u,
                EdgeColor = BinaryPrimitives.ReverseEndianness(sheetColor) | 0xFF000000u,
                WrapWidth = float.PositiveInfinity,
            });
    }

    private bool DrawColorColumn(uint sheetColor)
    {
        sheetColor = BinaryPrimitives.ReverseEndianness(sheetColor);
        var rgbtext = $"#{sheetColor & 0xFF:X02}{(sheetColor >> 8) & 0xFF:X02}{(sheetColor >> 16) & 0xFF:X02}";
        var size = new Vector2(ImGui.GetFrameHeight());
        size.X += ImGui.CalcTextSize(rgbtext).X + ImGui.GetStyle().FramePadding.X;

        var off = ImGui.GetCursorScreenPos();
        ImGui.GetWindowDrawList().AddRectFilled(
            off,
            off + new Vector2(size.Y),
            sheetColor | 0xFF000000u);
        ImGui.GetWindowDrawList().AddText(
            off + ImGui.GetStyle().FramePadding + new Vector2(size.Y, 0),
            ImGui.GetColorU32(ImGuiCol.Text),
            rgbtext);

        if (ImGui.InvisibleButton("##copy"u8, size))
        {
            ImGui.SetClipboardText(rgbtext);
            Service<NotificationManager>.Get().AddNotification(
                new()
                {
                    Content = $"已复制“{rgbtext}”。",
                    Title = this.DisplayName,
                    Type = NotificationType.Success,
                });
        }

        return ImGui.IsItemHovered();
    }
}
