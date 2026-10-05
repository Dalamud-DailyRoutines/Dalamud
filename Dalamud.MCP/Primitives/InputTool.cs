using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>input</c> 原语：注入键鼠输入。
/// </summary>
internal static class InputTool
{
    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: key（按键）、mouse（鼠标）。</param>
    /// <param name="key">key 模式的虚拟键名，取自 VirtualKey 枚举，例如 W、A、S、D、F1、SPACE、RETURN、ESCAPE，大小写不敏感。</param>
    /// <param name="mouse">mouse 模式的动作: move（移动到坐标）、left（左键点击）、right（右键点击）、middle（中键点击）、wheel（滚轮）。</param>
    /// <param name="x">客户区 X 坐标，以渲染帧像素为基准，与 capture 一致。</param>
    /// <param name="y">客户区 Y 坐标，以渲染帧像素为基准，与 capture 一致。</param>
    /// <param name="wheel">滚轮增量。</param>
    /// <param name="activate">为 true 时先请求把游戏窗口切到前台；默认 false，窗口不在前台时直接报错而不切换。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? key      = null,
        string? mouse    = null,
        int     x        = 0,
        int     y        = 0,
        int     wheel    = 0,
        bool    activate = false
    )
    {
        return action.ToLowerInvariant() switch
        {
            "key" => InputSender.SendKey
            (
                string.IsNullOrWhiteSpace(key) ? throw new McpException("key 模式需要提供 key。") : key,
                activate
            ),
            "mouse" => InputSender.SendMouse
            (
                string.IsNullOrWhiteSpace(mouse) ? "left" : mouse,
                x,
                y,
                wheel,
                activate
            ),
            _ => throw new McpException($"不支持的操作 \"{action}\"，可用值为 key、mouse。")
        };
    }
}
