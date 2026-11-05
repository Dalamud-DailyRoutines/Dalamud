using System.ComponentModel;

namespace Dalamud;

/// <summary>
/// <c>trace</c> 原语：读取服务器自身记录的操作流水。
/// </summary>
internal static class TraceTool
{
    /// <summary>
    /// 筛选并分页读取 trace 文件，限制响应大小。
    /// </summary>
    /// <param name="maxLines">最多返回的记录条数。</param>
    /// <param name="filter">按内容做不区分大小写的包含匹配。</param>
    /// <param name="before">上一页返回的 nextBefore，零表示读取最新记录。</param>
    /// <param name="maxCharacters">返回的 JSON 字符数上限。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        [Description("最多返回的记录条数，默认 20，最大 100。")]
        int maxLines = 20,
        [Description("先筛选整个当前日志文件，再分页；不区分大小写。")]
        string? filter = null,
        [Description("上一页的 nextBefore，零表示从最新记录开始；日志轮转后重新从零开始。")]
        int before = 0,
        [Description("结果 JSON 字符预算，默认 8192，范围 2048 至 16384；超长记录返回截断预览。")]
        int maxCharacters = 8192
    ) => MCPRuntime.Trace.Tail(Math.Clamp(maxLines, 1, 100), filter, Math.Max(before, 0), Math.Clamp(maxCharacters, 2048, 16384));
}
