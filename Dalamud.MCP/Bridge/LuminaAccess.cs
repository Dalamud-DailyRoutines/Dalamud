using System.Collections.Generic;
using System.Linq;
using System.Text;
using Dalamud.Data;
using Lumina.Excel;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 通过 Lumina 读取游戏数据表。
/// </summary>
internal static class LuminaAccess
{
    /// <summary>
    /// 列出表名。
    /// </summary>
    /// <param name="filter">按表名做不区分大小写的包含匹配。</param>
    /// <param name="offset">偏移。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <returns>JSON 文本。</returns>
    public static string ListSheets
    (
        string? filter,
        int     offset,
        int     limit
    )
    {
        var names = Service<DataManager>.Get().GameData.Excel.SheetNames;

        var filtered = names
                       .Where(name => string.IsNullOrWhiteSpace(filter) || name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                       .ToArray();

        var builder = new StringBuilder(2048);
        builder.Append("{\"total\":").Append(filtered.Length).Append(",\"sheets\":[");

        var page = filtered.Skip(Math.Max(offset, 0)).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append(ValueFormatter.Format(page[index], 0));
        }

        builder.Append("]}");
        return builder.ToString();
    }

    /// <summary>
    /// 列出表的行 id。
    /// </summary>
    /// <param name="sheetName">表名。</param>
    /// <param name="offset">偏移。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <returns>JSON 文本。</returns>
    public static string ReadRows
    (
        string sheetName,
        int    offset,
        int    limit
    )
    {
        var sheet = GetSheet(sheetName);
        var ids   = new List<uint>();

        foreach (var row in sheet)
            ids.Add(row.RowId);

        ids.Sort();

        var builder = new StringBuilder(2048);
        builder.Append("{\"sheet\":").Append(ValueFormatter.Format(sheetName, 0));
        builder.Append(",\"count\":").Append(ids.Count).Append(",\"rowIds\":[");

        var page = ids.Skip(Math.Max(offset, 0)).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append(page[index]);
        }

        builder.Append("]}");
        return builder.ToString();
    }

    /// <summary>
    /// 读出一行。
    /// </summary>
    /// <param name="sheetName">表名。</param>
    /// <param name="rowId">行 id。</param>
    /// <param name="maxColumns">最多返回列数。</param>
    /// <returns>JSON 文本。</returns>
    public static string ReadRow
    (
        string sheetName,
        uint   rowId,
        int    maxColumns
    )
    {
        var sheet = GetSheet(sheetName);

        foreach (var row in sheet)
        {
            if (row.RowId != rowId)
                continue;

            var columns = row.Columns;
            var builder = new StringBuilder(1024);
            builder.Append("{\"sheet\":").Append(ValueFormatter.Format(sheetName, 0));
            builder.Append(",\"rowId\":").Append(rowId);
            builder.Append(",\"columns\":[");

            var count = Math.Min(columns.Count, Math.Max(maxColumns, 1));

            for (var index = 0; index < count; index++)
            {
                if (index > 0)
                    builder.Append(',');

                builder.Append('{');
                builder.Append("\"index\":").Append(index);
                builder.Append(",\"type\":").Append(ValueFormatter.Format(columns[index].Type.ToString(), 0));

                object? value;

                try
                {
                    value = row.ReadColumn(index);
                }
                catch (Exception exception)
                {
                    value = "<读取失败: " + exception.GetType().Name + ">";
                }

                builder.Append(",\"value\":").Append(FormatValue(value));
                builder.Append('}');
            }

            builder.Append("]}");
            return builder.ToString();
        }

        throw new McpException($"表 {sheetName} 中没有行 {rowId}。");
    }

    /// <summary>
    /// 在指定列上做比较查找，列为负数时在全部列上查找。
    /// </summary>
    /// <param name="sheetName">表名。</param>
    /// <param name="column">列索引，负数表示全部列。</param>
    /// <param name="value">目标值文本。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Search
    (
        string sheetName,
        int    column,
        string value,
        int    limit
    )
    {
        var sheet   = GetSheet(sheetName);
        var matches = new List<(uint RowId, int Column)>();

        foreach (var row in sheet)
        {
            var columns = row.Columns.Count;
            var from    = column >= 0 ? column : 0;
            var to      = column >= 0 ? Math.Min(column + 1, columns) : columns;
            var matched = -1;

            for (var candidate = from; candidate < to; candidate++)
            {
                if (!FormatValue(row.ReadColumn(candidate)).Contains(value, StringComparison.OrdinalIgnoreCase))
                    continue;

                matched = candidate;
                break;
            }

            if (matched < 0)
                continue;

            matches.Add((row.RowId, matched));

            if (matches.Count >= limit)
                break;
        }

        var builder = new StringBuilder(1024);
        builder.Append("{\"sheet\":").Append(ValueFormatter.Format(sheetName, 0));
        builder.Append(",\"column\":").Append(column);
        builder.Append(",\"count\":").Append(matches.Count).Append(",\"matches\":[");

        for (var index = 0; index < matches.Count; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append('{');
            builder.Append("\"rowId\":").Append(matches[index].RowId);
            builder.Append(",\"column\":").Append(matches[index].Column);
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static ExcelSheet<RawRow> GetSheet
    (
        string sheetName
    )
    {
        if (string.IsNullOrWhiteSpace(sheetName))
            throw new McpException("需要提供表名。");

        return Service<DataManager>.Get().GameData.Excel.GetSheet<RawRow>(name: sheetName)
               ?? throw new McpException($"表 \"{sheetName}\" 不存在。");
    }

    private static string FormatValue
    (
        object? value
    ) => value switch
    {
        null        => "null",
        string text => ValueFormatter.Format(text,             0),
        _           => ValueFormatter.Format(value.ToString(), 0)
    };
}
