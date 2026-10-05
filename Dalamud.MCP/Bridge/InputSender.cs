using System.Linq;
using System.Threading;
using Dalamud.Game.ClientState.Keys;
using FFXIVClientStructs.FFXIV.Client.System.Input;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 向游戏注入键鼠输入。插件界面从窗口过程读取输入，走窗口消息；游戏本体走输入设备接口。
/// 窗口消息这条始终执行，设备接口失败只作为结果信息返回，不影响界面操作。
/// </summary>
internal static unsafe class InputSender
{
    private const int KEY_HOLD_MILLISECONDS = 30;

    /// <summary>
    /// 发送一次按键。
    /// </summary>
    /// <param name="key">虚拟键名，取自 VirtualKey 枚举。</param>
    /// <returns>JSON 文本。</returns>
    public static string SendKey
    (
        string key
    )
    {
        var virtualKey = ParseKey(key);
        var window     = WindowInfo.GetGameWindow();

        if (window == 0)
            throw new McpException("取不到游戏窗口句柄。");

        NativeApi.PostMessage(window, NativeApi.WM_KEYDOWN, virtualKey, 0);
        Thread.Sleep(KEY_HOLD_MILLISECONDS);
        NativeApi.PostMessage(window, NativeApi.WM_KEYUP, virtualKey, 0);

        var deviceError = TrySendKeyToGameDevice(virtualKey);

        return "{\"key\":"                             +
               ValueFormatter.Format(key, 0)           +
               ",\"virtualKey\":"                      +
               virtualKey                              +
               ",\"toWindow\":true"                    +
               ",\"toGameDevice\":"                    +
               (deviceError is null ? "true" : "false") +
               ",\"gameDeviceError\":"                 +
               ValueFormatter.Format(deviceError, 0)   +
               "}";
    }

    /// <summary>
    /// 发送鼠标动作。
    /// </summary>
    /// <param name="action">动作: move、left、right、middle、wheel。</param>
    /// <param name="x">客户区 X 坐标，以渲染帧像素为基准，与 capture 一致，可带小数。</param>
    /// <param name="y">客户区 Y 坐标，以渲染帧像素为基准，与 capture 一致，可带小数。</param>
    /// <param name="wheel">滚轮增量。</param>
    /// <returns>JSON 文本。</returns>
    public static string SendMouse
    (
        string action,
        double x,
        double y,
        double wheel
    )
    {
        var window = WindowInfo.GetGameWindow();
        if (window == 0)
            throw new McpException("取不到游戏窗口句柄。");

        var normalized = action.ToLowerInvariant();
        var pointX     = (int)Math.Round(x);
        var pointY     = (int)Math.Round(y);
        var wheelDelta = (int)Math.Round(wheel);
        var screen     = ToScreenPoint(window, pointX, pointY);
        var restored   = NativeApi.GetCursorPos(out var original);

        MCPRuntime.Trace.Write
        (
            "input",
            $"mouse window=0x{window:x} point=({pointX},{pointY}) screen=({screen.X},{screen.Y}) action={normalized}"
        );

        try
        {
            NativeApi.SetCursorPos(screen.X, screen.Y);

            switch (normalized)
            {
                case "move":
                    NativeApi.PostMessage(window, NativeApi.WM_MOUSEMOVE, 0, MakeLParam(pointX, pointY));
                    break;

                case "left":
                    PostClick(window, NativeApi.WM_LBUTTONDOWN, NativeApi.WM_LBUTTONUP, NativeApi.MK_LBUTTON, pointX, pointY);
                    break;

                case "right":
                    PostClick(window, NativeApi.WM_RBUTTONDOWN, NativeApi.WM_RBUTTONUP, NativeApi.MK_RBUTTON, pointX, pointY);
                    break;

                case "middle":
                    PostClick(window, NativeApi.WM_MBUTTONDOWN, NativeApi.WM_MBUTTONUP, NativeApi.MK_MBUTTON, pointX, pointY);
                    break;

                case "wheel":
                    NativeApi.PostMessage(window, NativeApi.WM_MOUSEWHEEL, wheelDelta << 16, MakeLParam(pointX, pointY));
                    break;

                default:
                    throw new McpException($"mouse 参数不接受 \"{action}\"，它只接受 move、left、right、middle、wheel 这五个动作名。动作名要填在 mouse 参数里，action 参数填 mouse；若只做左键单击，mouse 也可以整个省略。");
            }
        }
        finally
        {
            if (restored)
                NativeApi.SetCursorPos(original.X, original.Y);
        }

        var deviceError = TrySendMouseToGameDevice(normalized, pointX, pointY, wheelDelta);

        return "{\"detail\":"                                          +
               ValueFormatter.Format($"mouse={action} x={pointX} y={pointY}", 0) +
               ",\"toWindow\":true"                                    +
               ",\"toGameDevice\":"                                    +
               (deviceError is null ? "true" : "false")                +
               ",\"gameDeviceError\":"                                 +
               ValueFormatter.Format(deviceError, 0)                   +
               "}";
    }

    private static void PostClick
    (
        nint window,
        uint downMessage,
        uint upMessage,
        int  flag,
        int  x,
        int  y
    )
    {
        NativeApi.PostMessage(window, NativeApi.WM_MOUSEMOVE, 0, MakeLParam(x, y));
        NativeApi.PostMessage(window, downMessage, flag, MakeLParam(x, y));
        Thread.Sleep(KEY_HOLD_MILLISECONDS);
        NativeApi.PostMessage(window, upMessage, 0, MakeLParam(x, y));
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

    private static string? TrySendKeyToGameDevice
    (
        ushort virtualKey
    )
    {
        var manager = InputDeviceManager.Instance();
        if (manager is null || manager->KeyboardDevice is null)
            return "键盘设备当前不可用";

        try
        {
            ((KeyboardDeviceInterface*)manager->KeyboardDevice)->SendKey((SeVirtualKey)virtualKey);
            Thread.Sleep(KEY_HOLD_MILLISECONDS);
            return null;
        }
        catch (Exception exception)
        {
            return $"{exception.GetType().Name}: {exception.Message}";
        }
    }

    private static string? TrySendMouseToGameDevice
    (
        string action,
        int    x,
        int    y,
        int    wheel
    )
    {
        if (MouseDevice.MemberFunctionPointers.ScheduleCursorMove is null ||
            MouseDevice.MemberFunctionPointers.ProcessMouseInputMessage is null)
        {
            return "游戏的鼠标函数签名未解析";
        }

        var window = WindowInfo.GetGameWindow();
        if (window == 0)
            return "取不到游戏窗口句柄";

        try
        {
            MouseDevice.ScheduleCursorMove(x, y);

            switch (action)
            {
                case "left":
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_LBUTTONDOWN, NativeApi.MK_LBUTTON);
                    Thread.Sleep(KEY_HOLD_MILLISECONDS);
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_LBUTTONUP, 0);
                    break;

                case "right":
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_RBUTTONDOWN, NativeApi.MK_RBUTTON);
                    Thread.Sleep(KEY_HOLD_MILLISECONDS);
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_RBUTTONUP, 0);
                    break;

                case "middle":
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_MBUTTONDOWN, NativeApi.MK_MBUTTON);
                    Thread.Sleep(KEY_HOLD_MILLISECONDS);
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_MBUTTONUP, 0);
                    break;

                case "wheel":
                    MouseDevice.ProcessMouseInputMessage(window, NativeApi.WM_MOUSEWHEEL, wheel << 16);
                    break;
            }

            return null;
        }
        catch (Exception exception)
        {
            return $"{exception.GetType().Name}: {exception.Message}";
        }
    }

    private static nint MakeLParam
    (
        int x,
        int y
    ) => (y << 16) | (x & 0xFFFF);

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
}
