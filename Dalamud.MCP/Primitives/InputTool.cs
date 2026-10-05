using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>input</c> 原语：直接向游戏注入键鼠输入，或执行游戏内斜杠命令。
/// </summary>
internal static class InputTool
{
    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型，只接受三个值: key（按键）、mouse（鼠标）、command（执行游戏内斜杠命令）。</param>
    /// <param name="key">key 模式的虚拟键名，取自 VirtualKey 枚举，例如 W、A、S、D、F1、SPACE、RETURN、ESCAPE，大小写不敏感。</param>
    /// <param name="mouse">action 取 mouse 时，动作名填在这里，只接受 move（移动到坐标）、left（左键单击）、right（右键单击）、middle（中键单击）、wheel（滚轮）五个值；整个省略时按 left 处理。</param>
    /// <param name="x">客户区 X 坐标，以渲染帧像素为基准，与 capture 一致，可带小数。</param>
    /// <param name="y">客户区 Y 坐标，以渲染帧像素为基准，与 capture 一致，可带小数。</param>
    /// <param name="wheel">滚轮增量，action 取 mouse 且 mouse 取 wheel 时使用。</param>
    /// <param name="command">action 取 command 时的斜杠命令文本，例如 /pdr，会在框架线程上执行。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? key     = null,
        string? mouse   = null,
        double  x       = 0,
        double  y       = 0,
        double  wheel   = 0,
        string? command = null
    )
    {
        var normalized = action.ToLowerInvariant();

        MCPRuntime.Trace.Write
        (
            "input",
            $"action={action} key={key} mouse={mouse} x={x} y={y} wheel={wheel} command={command}"
        );

        try
        {
            return normalized switch
            {
                "key" => InputSender.SendKey
                (
                    string.IsNullOrWhiteSpace(key) ? throw new McpException("key 模式需要提供 key。") : key
                ),
                "mouse" => InputSender.SendMouse
                (
                    string.IsNullOrWhiteSpace(mouse) ? "left" : mouse,
                    x,
                    y,
                    wheel
                ),
                "command" => CommandSender.Send(command),
                _         => throw new McpException($"action 参数只接受 key、mouse、command 三个值，收到的是 \"{action}\"。")
            };
        }
        catch (McpException exception)
        {
            MCPRuntime.Trace.Write("input", $"被拒绝: {exception.Message}");
            throw;
        }
        catch (Exception exception)
        {
            MCPRuntime.Trace.Write("input", $"异常: {exception.GetType().FullName}: {exception.Message}");
            throw new McpException($"input 执行时抛出 {exception.GetType().FullName}: {exception.Message}");
        }
    }
}
