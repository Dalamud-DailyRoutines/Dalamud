using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Hooking;
using Dalamud.Game;
using Dalamud.Interface.ImGuiBackend.InputHandler;
using Dalamud.Interface.Internal;
using FFXIVClientStructs.FFXIV.Client.System.Input;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>在输入消费前覆盖合成状态，并以实际消费的帧数推进播放。</summary>
internal sealed class InputPlayback
(
    IReadOnlyList<InputFrame> frames,
    bool                      plugin
) : IDisposable
{
    private readonly Lock                 gate         = new();
    private readonly TaskCompletionSource completion   = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly HashSet<ushort>      previousKeys = [];
    private          Hook<DeviceUpdate>?  mouseHook;
    private          Hook<DeviceUpdate>?  keyboardHook;
    private          MouseButtonFlags     previousButtons;
    private          int                  index;
    private          bool                 mouseRead;
    private          bool                 keyboardRead;
    private          bool                 disposed;
    private          bool?                originalTrickle;

    public bool Plugin { get; } = plugin;

    public Task Completion => this.completion.Task;

    private delegate void DeviceUpdate(nint device, float delta);

    public unsafe void Install()
    {
        if (this.Plugin)
            return;

        var manager = InputDeviceManager.Instance();
        if (manager is null || manager->MouseDevice is null || manager->KeyboardDevice is null)
            throw new McpException("游戏输入设备尚未就绪。");

        try
        {
            this.mouseHook    = Hook<DeviceUpdate>.FromAddress((*(nint**)manager->MouseDevice)[2],    this.UpdateMouse);
            this.keyboardHook = Hook<DeviceUpdate>.FromAddress((*(nint**)manager->KeyboardDevice)[2], this.UpdateKeyboard);
            this.mouseHook.Enable();
            this.keyboardHook.Enable();
        }
        catch
        {
            this.Dispose();
            throw;
        }
    }

    public unsafe void Dispose()
    {
        lock (this.gate)
        {
            if (this.disposed)
                return;

            this.disposed = true;
            this.completion.TrySetCanceled();

            if (this.Plugin)
            {
                var keys = this.previousKeys.ToArray();
                _ = Service<InterfaceManager>.GetNullable()?.RunBeforeImGuiRender
                (() =>
                    {
                        var io = ImGui.GetIO();
                        ImGui.GetCurrentContext().Handle->InputEventsQueue.Resize(0);
                        if (this.originalTrickle is { } trickle)
                            io.ConfigInputTrickleEventQueue = trickle;

                        io.AddFocusEvent(NativeApi.GetForegroundWindow() == WindowInfo.GetGameWindow());
                        for (var button = 0; button < 3; button++)
                            io.AddMouseButtonEvent(button, false);

                        foreach (var key in keys)
                        {
                            var mapped = Win32InputHandler.VirtualKeyToImGuiKey(key);
                            if (mapped != ImGuiKey.None)
                                io.AddKeyEvent(mapped, false);
                        }

                        io.AddKeyEvent(ImGuiKey.ModCtrl,  false);
                        io.AddKeyEvent(ImGuiKey.ModShift, false);
                        io.AddKeyEvent(ImGuiKey.ModAlt,   false);
                    }
                );
            }
            else
            {
                _ = Service<Framework>.GetNullable()?.Run(this.ReleaseGameState, CancellationToken.None);
            }
        }

        this.mouseHook?.Dispose();
        this.keyboardHook?.Dispose();
    }

    public unsafe bool ApplyImGui()
    {
        lock (this.gate)
        {
            if (this.disposed || !this.Plugin || this.index >= frames.Count)
                return false;

            var io    = ImGui.GetIO();
            var frame = frames[this.index];
            this.originalTrickle            ??= io.ConfigInputTrickleEventQueue;
            io.ConfigInputTrickleEventQueue =   false;
            ImGui.GetCurrentContext().Handle->InputEventsQueue.Resize(0);
            io.AddFocusEvent(true);

            if (frame.X is { } x && frame.Y is { } y)
            {
                var viewport = ImGui.GetMainViewport();
                io.AddMouseViewportEvent(viewport.ID);
                io.AddMousePosEvent((float)x + viewport.Pos.X, (float)y + viewport.Pos.Y);
            }

            io.AddMouseButtonEvent(0, (frame.Buttons & MouseButtonFlags.LBUTTON) != 0);
            io.AddMouseButtonEvent(1, (frame.Buttons & MouseButtonFlags.RBUTTON) != 0);
            io.AddMouseButtonEvent(2, (frame.Buttons & MouseButtonFlags.MBUTTON) != 0);

            foreach (var key in this.previousKeys.Union(frame.Keys))
            {
                var mapped = Win32InputHandler.VirtualKeyToImGuiKey(key);
                if (mapped != ImGuiKey.None)
                    io.AddKeyEvent(mapped, frame.Keys.Contains(key));
            }

            io.AddKeyEvent(ImGuiKey.ModCtrl,  frame.Keys.Any(key => key is 0x11 or 0xA2 or 0xA3));
            io.AddKeyEvent(ImGuiKey.ModShift, frame.Keys.Any(key => key is 0x10 or 0xA0 or 0xA1));
            io.AddKeyEvent(ImGuiKey.ModAlt,   frame.Keys.Any(key => key is 0x12 or 0xA4 or 0xA5));
            if (frame.Wheel != 0)
                io.AddMouseWheelEvent(0, frame.Wheel);

            if (frame.Text is { } text)
                io.AddInputCharacters(text);

            this.previousKeys.Clear();
            this.previousKeys.UnionWith(frame.Keys);
            this.Advance();
            return true;
        }
    }

    private unsafe void UpdateMouse(nint device, float delta)
    {
        this.mouseHook!.Original(device, delta);

        lock (this.gate)
        {
            if (this.disposed || this.index >= frames.Count)
                return;

            var data = ((MouseDeviceInterface*)device)->GetData();

            if (data is null)
            {
                this.completion.TrySetException(new McpException("鼠标输入缓冲不可用。"));
                return;
            }

            var frame = frames[this.index];

            if (frame.X is { } x && frame.Y is { } y)
            {
                var (renderWidth, renderHeight) = WindowInfo.GetRenderSize();
                var (clientWidth, clientHeight) = WindowInfo.GetClientSize();

                if (renderWidth <= 0 || renderHeight <= 0 || clientWidth <= 0 || clientHeight <= 0)
                {
                    this.completion.TrySetException(new McpException("播放期间窗口尺寸失效。"));
                    return;
                }

                var nextX = (int)Math.Round(x * clientWidth  / renderWidth);
                var nextY = (int)Math.Round(y * clientHeight / renderHeight);
                data->DeltaX    = nextX - data->PositionX;
                data->DeltaY    = nextY - data->PositionY;
                data->PositionX = nextX;
                data->PositionY = nextY;
            }

            data->IsGameWindowFocused           = true;
            data->MouseButtonHeldFlags          = frame.Buttons;
            data->MouseButtonPressedFlags       = frame.Buttons        & ~this.previousButtons;
            data->MouseButtonReleasedFlags      = this.previousButtons & ~frame.Buttons;
            data->MouseButtonHeldThrottledFlags = data->MouseButtonPressedFlags;
            data->MouseWheel = this.mouseRead ?
                                   0 :
                                   frame.Wheel;
            this.previousButtons = frame.Buttons;
            this.mouseRead       = true;
            if (this.keyboardRead)
                this.Advance();
        }
    }

    private unsafe void UpdateKeyboard(nint device, float delta)
    {
        this.keyboardHook!.Original(device, delta);

        lock (this.gate)
        {
            if (this.disposed || this.index >= frames.Count)
                return;

            var data = ((KeyboardDeviceInterface*)device)->GetData();

            if (data is null)
            {
                this.completion.TrySetException(new McpException("键盘输入缓冲不可用。"));
                return;
            }

            var frame = frames[this.index];

            foreach (var key in this.previousKeys.Union(frame.Keys))
            {
                var down  = frame.Keys.Contains(key);
                var state = KeyStateFlags.Released;

                if (down)
                {
                    state = KeyStateFlags.Down;
                    if (!this.previousKeys.Contains(key))
                        state |= KeyStateFlags.Pressed;
                }

                data->KeyState[key] = state;
            }

            this.previousKeys.Clear();
            this.previousKeys.UnionWith(frame.Keys);
            this.keyboardRead = true;
            if (this.mouseRead)
                this.Advance();
        }
    }

    private void Advance()
    {
        this.mouseRead    = false;
        this.keyboardRead = false;
        this.index++;
        if (this.index == frames.Count)
            this.completion.TrySetResult();
    }

    private unsafe void ReleaseGameState()
    {
        var manager = InputDeviceManager.Instance();
        if (manager is null)
            return;

        if (manager->KeyboardDevice is not null)
        {
            var data = ((KeyboardDeviceInterface*)manager->KeyboardDevice)->GetData();

            if (data is not null)
            {
                foreach (var key in this.previousKeys)
                    data->KeyState[key] = KeyStateFlags.Released;
            }
        }

        if (manager->MouseDevice is not null)
        {
            var data = ((MouseDeviceInterface*)manager->MouseDevice)->GetData();

            if (data is not null)
            {
                data->MouseButtonHeldFlags     &= ~this.previousButtons;
                data->MouseButtonPressedFlags  &= ~this.previousButtons;
                data->MouseButtonReleasedFlags |= this.previousButtons;
                data->MouseWheel               =  0;
            }
        }
    }
}
