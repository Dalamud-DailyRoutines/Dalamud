using System.Collections.Generic;
using System.Linq;
using Dalamud.Game.ClientState.Keys;
using Dalamud.Interface.ImGuiBackend.InputHandler;
using Dalamud.Bindings.ImGui;
using FFXIVClientStructs.FFXIV.Client.System.Input;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>先验证全部动作，再生成可逐帧播放的输入计划。</summary>
internal static class InputPlan
{
    public static IReadOnlyList<InputFrame> Create(InputAction[] actions, CapturedFrame? reference, bool plugin, int width, int height)
    {
        if (actions.Length is < 1 or > 64)
            throw new McpException("actions 需要 1 至 64 项动作。");

        var     frames   = new List<InputFrame>();
        double? currentX = null;
        double? currentY = null;

        foreach (var action in actions)
        {
            if (action is null || action.Frames is < 2 or > 120)
                throw new McpException("动作不能为空，frames 必须在 2 至 120 之间。");

            var kind = action.Action;
            if (action.X.HasValue != action.Y.HasValue)
                throw new McpException("X 与 Y 必须同时提供。");

            if (action.X is { } x && action.Y is { } y)
                (currentX, currentY) = Resolve(x, y, reference, width, height);

            var idle = new InputFrame(currentX, currentY, MouseButtonFlags.None, []);

            if (kind is "move" or "click" or "double_click" or "drag" or "scroll")
            {
                if (currentX is null || currentY is null)
                    throw new McpException("鼠标操作需要明确的 X、Y 坐标，或前一动作已指定的位置。");

                frames.Add(idle);
                frames.Add(idle);
            }

            switch (kind)
            {
                case "move":
                case "wait":
                    for (var index = 0; index < action.Frames; index++)
                        frames.Add(idle);

                    break;
                case "click":
                case "double_click":
                    var button = ParseButton(action.Button);
                    var count = kind == "double_click" ?
                                    2 :
                                    1;

                    for (var click = 0; click < count; click++)
                    {
                        for (var index = 0; index < action.Frames; index++)
                            frames.Add(idle with { Buttons = button });

                        frames.Add(idle);
                        frames.Add(idle);
                    }

                    break;
                case "drag":
                    if (action.EndX is not { } endX || action.EndY is not { } endY)
                        throw new McpException("drag 需要 EndX、EndY。");

                    var end  = Resolve(endX, endY, reference, width, height);
                    var held = ParseButton(action.Button);
                    frames.Add(idle with { Buttons = held });
                    frames.Add(idle with { Buttons = held });

                    for (var index = 1; index <= action.Frames; index++)
                    {
                        var ratio = (double)index / action.Frames;
                        frames.Add
                        (
                            idle with
                            {
                                X = currentX + ((end.X - currentX) * ratio),
                                Y = currentY + ((end.Y - currentY) * ratio),
                                Buttons = held
                            }
                        );
                    }

                    currentX = end.X;
                    currentY = end.Y;
                    idle     = idle with { X = currentX, Y = currentY };
                    frames.Add(idle);
                    frames.Add(idle);
                    break;
                case "scroll":
                    if (action.Wheel is 0 or < -120 or > 120)
                        throw new McpException("Wheel 必须为 -120 至 120 之间的非零整数格数。");

                    frames.Add(idle with { Wheel = action.Wheel });
                    frames.Add(idle);
                    break;
                case "key":
                    if (action.Keys is not { Length: > 0 and <= 8 })
                        throw new McpException("key 需要 1 至 8 项 Keys。");

                    var keys      = action.Keys.Select(key => ParseKey(key, plugin)).Distinct().ToArray();
                    var modifiers = keys.Where(key => key is 0x10 or 0x11 or 0x12 or >= 0xA0 and <= 0xA5).ToArray();
                    frames.Add(idle with { Keys = modifiers });
                    frames.Add(idle with { Keys = modifiers });
                    for (var index = 0; index < action.Frames; index++)
                        frames.Add(idle with { Keys = keys });

                    frames.Add(idle with { Keys = modifiers });
                    frames.Add(idle);
                    frames.Add(idle);
                    break;
                case "text":
                    if (!plugin || string.IsNullOrEmpty(action.Text) || action.Text.Length > 4096)
                        throw new McpException("text 仅支持 plugin 目标，文本长度为 1 至 4096 个字符。");

                    frames.Add(idle with { Text = action.Text });
                    frames.Add(idle);
                    break;
                default:
                    throw new McpException($"未知输入动作：{kind}。");
            }

            if (frames.Count > 1800)
                throw new McpException("输入计划不能超过 1800 帧，请拆分调用。");
        }

        return frames;
    }

    private static (double X, double Y) Resolve(double x, double y, CapturedFrame? reference, int width, int height)
    {
        if (reference is not null)
            return reference.ToRender(x, y);

        if (!double.IsFinite(x) || !double.IsFinite(y) || x < 0 || y < 0 || x >= width || y >= height)
            throw new McpException("输入坐标超出当前渲染帧范围。");

        return (x, y);
    }

    private static MouseButtonFlags ParseButton(string button) => button switch
    {
        "left"   => MouseButtonFlags.LBUTTON,
        "right"  => MouseButtonFlags.RBUTTON,
        "middle" => MouseButtonFlags.MBUTTON,
        _        => throw new McpException("Button 只接受 left、right、middle。")
    };

    private static ushort ParseKey(string key, bool plugin)
    {
        if (!Enum.TryParse<VirtualKey>(key, true, out var parsed) || !Enum.IsDefined(parsed) || parsed == VirtualKey.NO_KEY)
            throw new McpException($"无效 VirtualKey 名称：{key}。");

        var value = (ushort)parsed;
        return plugin switch
        {
            false when value >= 159 => throw new McpException($"游戏键盘缓冲不支持按键 {key}。"),
            true when value is not (0x10 or 0x11 or 0x12) && Win32InputHandler.VirtualKeyToImGuiKey(value) == ImGuiKey.None => throw new McpException
                                                                                                                                   ($"ImGui 不支持按键 {key}。"),
            _ => value
        };
    }
}
