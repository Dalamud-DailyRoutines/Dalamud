using System.Linq;
using System.Numerics;

using Dalamud.Bindings.ImGui;
using Dalamud.Game.Gui.FlyText;
using Dalamud.Interface.Utility.Raii;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying fly text info.
/// </summary>
internal class FlyTextWidget : IDataWindowWidget
{
    private int flyActor;
    private FlyTextKind flyKind;
    private int flyVal1;
    private int flyVal2;
    private string flyText1 = string.Empty;
    private string flyText2 = string.Empty;
    private int flyIcon;
    private int flyDmgIcon;
    private Vector4 flyColor = new(1, 0, 0, 1);

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["flytext"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "飘字";

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
        using (var combo = ImRaii.Combo("类型"u8, $"{this.flyKind} ({(int)this.flyKind})"))
        {
            if (combo.Success)
            {
                foreach (var value in Enum.GetValues<FlyTextKind>().Distinct())
                {
                    if (ImGui.Selectable($"{value} ({(int)value})"))
                    {
                        this.flyKind = value;
                    }
                }
            }
        }

        ImGui.InputText("文本 1"u8, ref this.flyText1, 200);
        ImGui.InputText("文本 2"u8, ref this.flyText2, 200);

        ImGui.InputInt("数值 1"u8, ref this.flyVal1);
        ImGui.InputInt("数值 2"u8, ref this.flyVal2);

        ImGui.InputInt("图标 ID"u8, ref this.flyIcon);
        ImGui.InputInt("伤害图标 ID"u8, ref this.flyDmgIcon);
        ImGui.ColorEdit4("颜色", ref this.flyColor);
        ImGui.InputInt("角色索引"u8, ref this.flyActor);
        var sendColor = ImGui.ColorConvertFloat4ToU32(this.flyColor);

        if (ImGui.Button("发送"u8))
        {
            Service<FlyTextGui>.Get().AddFlyText(
                this.flyKind,
                unchecked((uint)this.flyActor),
                unchecked((uint)this.flyVal1),
                unchecked((uint)this.flyVal2),
                this.flyText1,
                this.flyText2,
                sendColor,
                unchecked((uint)this.flyIcon),
            unchecked((uint)this.flyDmgIcon));
        }
    }

}
