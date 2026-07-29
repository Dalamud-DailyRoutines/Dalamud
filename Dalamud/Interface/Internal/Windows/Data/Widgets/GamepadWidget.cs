using Dalamud.Bindings.ImGui;
using Dalamud.Game.ClientState.GamePad;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying gamepad info.
/// </summary>
internal class GamepadWidget : IDataWindowWidget
{
    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["gamepad", "controller"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "游戏手柄";

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
        var gamepadState = Service<GamepadState>.Get();

        ImGui.Text($"手柄输入 {Util.DescribeAddress(gamepadState.GamepadInputAddress)}");

#if DEBUG
        if (ImGui.IsItemHovered())
            ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

        if (ImGui.IsItemClicked())
            ImGui.SetClipboardText($"{Util.DescribeAddress(gamepadState.GamepadInputAddress)}");
#endif

        this.DrawHelper("原始按键", (uint)gamepadState.ButtonsRaw, gamepadState.Raw);
        this.DrawHelper("按下按键", (uint)gamepadState.ButtonsPressed, gamepadState.Pressed);
        this.DrawHelper("重复按键", (uint)gamepadState.ButtonsRepeat, gamepadState.Repeat);
        this.DrawHelper("松开按键", (uint)gamepadState.ButtonsReleased, gamepadState.Released);
        ImGui.Text($"左摇杆 {gamepadState.LeftStick}");
        ImGui.Text($"右摇杆 {gamepadState.RightStick}");
    }

    private void DrawHelper(string text, uint mask, Func<GamepadButtons, float> resolve)
    {
        ImGui.Text($"{text} {mask:X4}");
        ImGui.Text($"方向键左 {resolve(GamepadButtons.DpadLeft)} " +
                   $"方向键上 {resolve(GamepadButtons.DpadUp)} " +
                   $"方向键右 {resolve(GamepadButtons.DpadRight)} " +
                   $"方向键下 {resolve(GamepadButtons.DpadDown)} ");
        ImGui.Text($"西侧键 {resolve(GamepadButtons.West)} " +
                   $"北侧键 {resolve(GamepadButtons.North)} " +
                   $"东侧键 {resolve(GamepadButtons.East)} " +
                   $"南侧键 {resolve(GamepadButtons.South)} ");
        ImGui.Text($"L1 {resolve(GamepadButtons.L1)} " +
                   $"L2 {resolve(GamepadButtons.L2)} " +
                   $"R1 {resolve(GamepadButtons.R1)} " +
                   $"R2 {resolve(GamepadButtons.R2)} ");
        ImGui.Text($"选择 {resolve(GamepadButtons.Select)} " +
                   $"开始 {resolve(GamepadButtons.Start)} " +
                   $"L3 {resolve(GamepadButtons.L3)} " +
                   $"R3 {resolve(GamepadButtons.R3)} ");
    }
}
