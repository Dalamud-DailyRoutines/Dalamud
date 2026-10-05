using System.Linq;
using System.Text;

namespace Dalamud;

/// <summary>
/// <c>trace</c> 原语：读取服务器自身记录的操作流水。
/// </summary>
internal static class TraceTool
{
    /// <summary>
    /// 读取 trace 文件尾部。
    /// </summary>
    /// <param name="maxLines">最多返回的记录条数。</param>
    /// <param name="filter">按内容做不区分大小写的包含匹配。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        int     maxLines = 50,
        string? filter   = null
    )
    {
        var lines = MCPRuntime.Trace.Tail(Math.Clamp(maxLines, 1, 2000));

        if (!string.IsNullOrWhiteSpace(filter))
            lines = [.. lines.Where(line => line.Contains(filter, StringComparison.OrdinalIgnoreCase))];

        var builder = new StringBuilder(1024);
        builder.Append("{\"file\":\"").Append(Escape(MCPRuntime.Trace.FilePath)).Append("\",\"lines\":[");

        for (var index = 0; index < lines.Length; index++)
        {
            if (index > 0)
                builder.Append(',');
            builder.Append(lines[index]);
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string Escape
    (
        string value
    ) => value.Replace(@"\", @"\\", StringComparison.Ordinal)
              .Replace("\"", "\\\"", StringComparison.Ordinal);
}
