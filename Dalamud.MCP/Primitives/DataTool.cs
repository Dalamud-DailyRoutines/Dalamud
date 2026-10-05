using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>data</c> 原语：读取游戏数据表。
/// </summary>
internal static class DataTool
{
    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: sheets、rows、row、search。</param>
    /// <param name="sheet">表名。</param>
    /// <param name="rowId">row 模式的行 id。</param>
    /// <param name="column">search 模式的列索引，省略或传负数表示在该表全部列上搜索。</param>
    /// <param name="value">sheets 的过滤词，或 search 的目标值。</param>
    /// <param name="offset">偏移。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? sheet  = null,
        uint    rowId  = 0,
        int     column = -1,
        string? value  = null,
        int     offset = 0,
        int     limit  = 32
    )
    {
        var page = Math.Clamp(limit, 1, 500);

        return action.ToLowerInvariant() switch
        {
            "sheets" => LuminaAccess.ListSheets(value, offset, page),
            "rows"   => LuminaAccess.ReadRows(Require(sheet, "rows 需要提供 sheet。"), offset, page),
            "row"    => LuminaAccess.ReadRow(Require(sheet,  "row 需要提供 sheet。"), rowId, page),
            "search" => LuminaAccess.Search
            (
                Require(sheet, "search 需要提供 sheet。"),
                column,
                Require(value, "search 需要提供 value。"),
                page
            ),
            _ => throw new McpException($"不支持的操作 \"{action}\"，可用值为 sheets、rows、row、search。")
        };
    }

    private static string Require
    (
        string? value,
        string  message
    ) =>
        string.IsNullOrWhiteSpace(value) ? throw new McpException(message) : value;
}
