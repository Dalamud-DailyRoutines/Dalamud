using System.Linq;
using System.Text;
using System.Threading;
using Dalamud.Game.ClientState.Keys;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 通过 SendInput 注入键鼠输入。需要游戏窗口在前台。
/// </summary>
internal static unsafe class InputSender
{
    private const int KEY_HOLD_MILLISECONDS   = 30;
    private const int FOCUS_WAIT_MILLISECONDS = 500;

    /// <summary>
    /// 发送一次按键的按下与抬起。
    /// </summary>
    /// <param name="key">虚拟键名，例如 A 或 F1。</param>
    /// <param name="activate">为 true 时先请求把游戏窗口切到前台。</param>
    /// <returns>JSON 文本。</returns>
    public static string SendKey
    (
        string key,
        bool   activate
    )
    {
        var virtualKey = ParseKey(key);
        var scanCode   = (ushort)NativeApi.MapVirtualKey(virtualKey, NativeApi.MAPVK_VK_TO_VSC);
        var window     = WindowInfo.GetGameWindow();

        EnsureForeground(window, activate);

        SendKeyboard(virtualKey, scanCode, 0);
        Thread.Sleep(KEY_HOLD_MILLISECONDS);
        SendKeyboard(virtualKey, scanCode, NativeApi.KEYEVENTF_KEYUP);

        return Describe(window, $"key={key} virtualKey={virtualKey} scanCode={scanCode}");
    }

    /// <summary>
    /// 发送鼠标动作。
    /// </summary>
    /// <param name="action">动作: move、left、right、middle、wheel。</param>
    /// <param name="x">客户区 X 坐标，以渲染帧像素为基准，与 capture 一致。</param>
    /// <param name="y">客户区 Y 坐标，以渲染帧像素为基准，与 capture 一致。</param>
    /// <param name="wheel">滚轮增量。</param>
    /// <param name="activate">为 true 时先请求把游戏窗口切到前台。</param>
    /// <returns>JSON 文本。</returns>
    public static string SendMouse
    (
        string action,
        int    x,
        int    y,
        int    wheel,
        bool   activate
    )
    {
        var window = WindowInfo.GetGameWindow();

        EnsureForeground(window, activate);

        switch (action.ToLowerInvariant())
        {
            case "move":
                SendMouseInput(window, NativeApi.MOUSEEVENTF_MOVE, x, y, 0);
                break;

            case "left":
            case "right":
            case "middle":
            {
                var (down, up) = action.ToLowerInvariant() switch
                {
                    "left"  => (NativeApi.MOUSEEVENTF_LEFTDOWN, NativeApi.MOUSEEVENTF_LEFTUP),
                    "right" => (NativeApi.MOUSEEVENTF_RIGHTDOWN, NativeApi.MOUSEEVENTF_RIGHTUP),
                    _       => (NativeApi.MOUSEEVENTF_MIDDLEDOWN, NativeApi.MOUSEEVENTF_MIDDLEUP)
                };

                SendMouseInput(window, NativeApi.MOUSEEVENTF_MOVE, x, y, 0);
                SendMouseInput(window, down,                       x, y, 0);
                Thread.Sleep(KEY_HOLD_MILLISECONDS);
                SendMouseInput(window, up, x, y, 0);
                break;
            }

            case "wheel":
                SendMouseInput(window, NativeApi.MOUSEEVENTF_WHEEL, x, y, wheel);
                break;

            default:
                throw new McpException($"不支持的鼠标动作 \"{action}\"。");
        }

        return Describe(window, $"mouse={action} x={x} y={y}");
    }

    private static void EnsureForeground
    (
        nint window,
        bool activate
    )
    {
        if (window == 0)
            throw new McpException("取不到游戏窗口句柄。");

        if (NativeApi.GetForegroundWindow() == window)
            return;

        if (!activate)
            throw new McpException("游戏窗口不在前台，注入的输入无法送达。要切换前台（会打断当前正在进行的操作）时，显式传 activate=true。");

        NativeApi.ShowWindow(window, NativeApi.SW_RESTORE);

        var targetThread  = NativeApi.GetWindowThreadProcessId(window, out _);
        var currentThread = NativeApi.GetCurrentThreadId();
        var attached      = targetThread != currentThread && NativeApi.AttachThreadInput(currentThread, targetThread, true);

        try
        {
            NativeApi.BringWindowToTop(window);
            _ = NativeApi.SetForegroundWindow(window);
            _ = NativeApi.SetFocus(window);
        }
        finally
        {
            if (attached)
                _ = NativeApi.AttachThreadInput(currentThread, targetThread, false);
        }

        var deadline = Environment.TickCount64 + FOCUS_WAIT_MILLISECONDS;
        while (NativeApi.GetForegroundWindow() != window && Environment.TickCount64 < deadline)
            Thread.Sleep(10);

        if (NativeApi.GetForegroundWindow() != window)
            throw new McpException("无法把游戏窗口切到前台。");
    }

    private static void SendMouseInput
    (
        nint window,
        uint flags,
        int  x,
        int  y,
        int  wheel
    )
    {
        var screen = ToScreenPoint(window, x, y);

        var left   = NativeApi.GetSystemMetrics(NativeApi.SM_XVIRTUALSCREEN);
        var top    = NativeApi.GetSystemMetrics(NativeApi.SM_YVIRTUALSCREEN);
        var width  = Math.Max(NativeApi.GetSystemMetrics(NativeApi.SM_CXVIRTUALSCREEN), 1);
        var height = Math.Max(NativeApi.GetSystemMetrics(NativeApi.SM_CYVIRTUALSCREEN), 1);

        var input = default(NativeApi.Input);
        input.Type                  = NativeApi.INPUT_MOUSE;
        input.Union.Mouse.Dx        = (int)((screen.X - left) * 65535L / (width  - 1));
        input.Union.Mouse.Dy        = (int)((screen.Y - top)  * 65535L / (height - 1));
        input.Union.Mouse.MouseData = (uint)wheel;
        input.Union.Mouse.Flags     = flags | NativeApi.MOUSEEVENTF_ABSOLUTE | NativeApi.MOUSEEVENTF_VIRTUALDESK;

        _ = NativeApi.SendInput(1, &input, sizeof(NativeApi.Input));
    }

    private static NativeApi.Point ToScreenPoint
    (
        nint window,
        int  x,
        int  y
    )
    {
        var (renderWidth, renderHeight) = WindowInfo.GetRenderSize();
        var (clientWidth, clientHeight) = WindowInfo.GetClientSize();

        var point = default(NativeApi.Point);

        if (renderWidth > 0 && renderHeight > 0 && clientWidth > 0 && clientHeight > 0)
        {
            point.X = (int)((long)x * clientWidth  / renderWidth);
            point.Y = (int)((long)y * clientHeight / renderHeight);
        }
        else
        {
            point.X = x;
            point.Y = y;
        }

        if (!NativeApi.ClientToScreen(window, ref point))
            throw new McpException("无法把客户区坐标换算成屏幕坐标。");

        return point;
    }

    private static ushort ParseKey
    (
        string key
    )
    {
        if (Enum.TryParse<VirtualKey>(key, true, out var virtualKey) && virtualKey != VirtualKey.NO_KEY)
            return (ushort)virtualKey;

        if (key.Length == 1 && char.IsLetterOrDigit(key[0]))
            return char.ToUpperInvariant(key[0]);

        var available = string.Join
        (
            ", ",
            Enum.GetNames<VirtualKey>().Where(name => name.Length <= 7).Take(40)
        );

        throw new McpException($"无法识别的按键 \"{key}\"。键名取自 VirtualKey 枚举，例如 W、A、S、D、F1、SPACE、RETURN、ESCAPE；一部分可用项: {available}");
    }

    private static void SendKeyboard
    (
        ushort virtualKey,
        ushort scanCode,
        uint   flags
    )
    {
        var input = default(NativeApi.Input);
        input.Type                      = NativeApi.INPUT_KEYBOARD;
        input.Union.Keyboard.VirtualKey = virtualKey;
        input.Union.Keyboard.ScanCode   = scanCode;
        input.Union.Keyboard.Flags      = flags;
        input.Union.Keyboard.Time       = 0;
        input.Union.Keyboard.ExtraInfo  = 0;

        _ = NativeApi.SendInput(1, &input, sizeof(NativeApi.Input));
    }

    private static string Describe
    (
        nint   window,
        string detail
    )
    {
        var builder = new StringBuilder(256);
        builder.Append("{\"detail\":").Append(ValueFormatter.Format(detail, 0));
        builder.Append(",\"window\":\"").Append(WindowInfo.Format(window)).Append('"');
        builder.Append(",\"isForeground\":").Append(NativeApi.GetForegroundWindow() == window ? "true" : "false");
        builder.Append('}');
        return builder.ToString();
    }
}
