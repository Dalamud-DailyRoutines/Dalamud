using System.Collections.Generic;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 把成员路径表达式拆成段序列。段之间用点号分隔，索引与字典键写作 <c>[i]</c> 或 <c>["key"]</c>。
/// </summary>
internal static class MemberPath
{
    /// <summary>
    /// 解析路径表达式。
    /// </summary>
    /// <param name="path">路径表达式，省略或为空时表示根本身。</param>
    /// <returns>段序列，按从根到叶的顺序排列。</returns>
    public static string[] Parse
    (
        string? path
    )
    {
        if (string.IsNullOrWhiteSpace(path))
            return [];

        var segments = new List<string>();
        var builder  = new StringBuilder();
        var index    = 0;

        while (index < path.Length)
        {
            var character = path[index];

            switch (character)
            {
                case '.':
                    Flush(segments, builder);
                    index++;
                    continue;

                case '[':
                    Flush(segments, builder);
                    var end = path.IndexOf(']', index);
                    if (end < 0)
                        throw new McpException($"路径 \"{path}\" 中的 \"[\" 没有配对的 \"]\"。");

                    var inner = path.AsSpan(index + 1, end - index - 1).Trim();
                    if (inner.Length >= 2 && (inner[0] == '"' || inner[0] == '\''))
                        inner = inner[1..^1];

                    segments.Add(inner.ToString());
                    index = end + 1;
                    continue;

                default:
                    builder.Append(character);
                    index++;
                    break;
            }
        }

        Flush(segments, builder);
        return [.. segments];
    }

    private static void Flush
    (
        List<string>  segments,
        StringBuilder builder
    )
    {
        if (builder.Length == 0)
            return;

        segments.Add(builder.ToString());
        builder.Clear();
    }
}
