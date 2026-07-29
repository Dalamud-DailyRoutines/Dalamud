using System.Numerics;

using Dalamud.Bindings.ImGui;
using Dalamud.Game.Gui.Toast;
using Dalamud.Interface.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying toast test.
/// </summary>
internal class ToastWidget : IDataWindowWidget
{
    private string inputTextToast = string.Empty;
    private int toastPosition;
    private int toastSpeed;
    private int questToastPosition;
    private bool questToastSound;
    private int questToastIconId;
    private bool questToastCheckmark;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["toast"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "浮窗通知";

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
        var toastGui = Service<ToastGui>.Get();

        ImGui.InputText("通知文本"u8, ref this.inputTextToast, 200);

        ImGui.Combo("通知位置", ref this.toastPosition, ["底部", "顶部",], 2);
        ImGui.Combo("通知速度", ref this.toastSpeed, ["慢", "快",], 2);
        ImGui.Combo("任务通知位置", ref this.questToastPosition, ["中间", "右侧", "左侧"], 3);
        ImGui.Checkbox("任务完成标记"u8, ref this.questToastCheckmark);
        ImGui.Checkbox("播放任务提示音"u8, ref this.questToastSound);
        ImGui.InputInt("任务图标 ID"u8, ref this.questToastIconId);

        ImGuiHelpers.ScaledDummy(new Vector2(10, 10));

        if (ImGui.Button("显示通知"u8))
        {
            toastGui.ShowNormal(this.inputTextToast, new ToastOptions
            {
                Position = (ToastPosition)this.toastPosition,
                Speed = (ToastSpeed)this.toastSpeed,
            });
        }

        if (ImGui.Button("显示任务通知"u8))
        {
            toastGui.ShowQuest(this.inputTextToast, new QuestToastOptions
            {
                Position = (QuestToastPosition)this.questToastPosition,
                DisplayCheckmark = this.questToastCheckmark,
                IconId = (uint)this.questToastIconId,
                PlaySound = this.questToastSound,
            });
        }

        if (ImGui.Button("显示错误通知"u8))
        {
            toastGui.ShowError(this.inputTextToast);
        }
    }
}
