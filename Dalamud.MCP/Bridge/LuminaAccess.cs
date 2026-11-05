using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Dalamud.Data;
using Lumina.Excel;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>按索引直接访问行，并提供列布局及连续分页。</summary>
internal static class LuminaAccess
{
    public static string ListSheets(string? filter, int offset, int limit)
    {
        var names = Service<DataManager>.Get().GameData.Excel.SheetNames
                                        .Where(name => filter is null || name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                                        .OrderBy(name => name, StringComparer.Ordinal).ToArray();
        var page = names.Skip(offset).Take(limit).ToArray();
        return JsonSerializer.Serialize
        (
            new
            {
                total = names.Length, offset, nextOffset = offset + page.Length < names.Length ?
                                                               (int?)(offset + page.Length) :
                                                               null,
                sheets = page
            }
        );
    }

    public static string Schema(string sheetName, int offset, int limit)
    {
        var columns = GetSheet(sheetName).Columns;
        return JsonSerializer.Serialize
        (
            new
            {
                sheet = sheetName,
                total = columns.Count,
                offset,
                nextOffset = offset + limit < columns.Count ?
                                 (int?)(offset + limit) :
                                 null,
                columns = columns.Skip(offset).Take(limit).Select
                    ((column, index) => new { index = index + offset, type = column.Type.ToString(), offset = column.Offset }).ToArray()
            }
        );
    }

    public static string ReadRows(string sheetName, int offset, int limit)
    {
        var ids = GetSheet(sheetName).Skip(offset).Take(limit + 1).Select(row => row.RowId).ToArray();
        return JsonSerializer.Serialize
        (
            new
            {
                sheet = sheetName, offset, nextOffset = ids.Length > limit ?
                                                            (int?)(offset + limit) :
                                                            null,
                rowIds = ids.Take(limit).ToArray()
            }
        );
    }

    public static string ReadRow(string sheetName, uint rowId, int offset, int limit)
    {
        var sheet = GetSheet(sheetName);
        if (!sheet.TryGetRow(rowId, out var row))
            throw new McpException($"表 {sheetName} 不包含行 {rowId}。");

        var columns = row.Columns;
        var page = columns.Skip(offset).Take(limit).Select
        ((column, index) =>
            {
                var position = offset + index;

                try
                {
                    return new { index = position, type = column.Type.ToString(), value = FormatValue(row.ReadColumn(position)), error = (string?)null };
                }
                catch (Exception exception)
                {
                    return new { index = position, type = column.Type.ToString(), value = (object?)null, error = exception.GetBaseException().Message };
                }
            }
        ).ToArray();
        return JsonSerializer.Serialize
        (
            new
            {
                sheet = sheetName, rowId, totalColumns = columns.Count, offset, nextOffset = offset + page.Length < columns.Count ?
                                                                                                 (int?)(offset + page.Length) :
                                                                                                 null,
                columns = page
            }
        );
    }

    public static string Search(string sheetName, int column, string value, int offset, int limit, CancellationToken cancellationToken)
    {
        var sheet = GetSheet(sheetName);
        if (column >= sheet.Columns.Count)
            throw new McpException($"列下标越界，表只有 {sheet.Columns.Count} 列。");

        var matches   = new List<object>();
        var examined  = 0;
        var exhausted = true;

        foreach (var row in sheet.Skip(offset))
        {
            cancellationToken.ThrowIfCancellationRequested();
            examined++;
            var from = column < 0 ?
                           0 :
                           column;
            var to = column < 0 ?
                         row.Columns.Count :
                         column + 1;

            for (var candidate = from; candidate < to; candidate++)
            {
                var cell = FormatValue(row.ReadColumn(candidate));
                if (!(cell?.ToString() ?? string.Empty).Contains(value, StringComparison.OrdinalIgnoreCase))
                    continue;

                matches.Add(new { rowId = row.RowId, column = candidate, value = cell });
                break;
            }

            if (matches.Count >= limit || examined >= 10000)
            {
                exhausted = false;
                break;
            }
        }

        return JsonSerializer.Serialize
        (
            new
            {
                sheet = sheetName, column, offset, examined, nextOffset = exhausted ?
                                                                              (int?)null :
                                                                              offset + examined,
                matches
            }
        );
    }

    private static ExcelSheet<RawRow> GetSheet(string sheetName) =>
        Service<DataManager>.Get().GameData.Excel.GetSheet<RawRow>(name: sheetName) ?? throw new McpException($"表 {sheetName} 不存在。");

    private static object? FormatValue(object? value)
    {
        if (value is null || value is string || value.GetType().IsPrimitive || value is decimal)
            return value;

        return value.ToString();
    }
}
