using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>mem_scan</c> 原语：特征码扫描、数值扫描与带会话的收敛过滤。
/// </summary>
internal static class MemScanTool
{
    private const string HEX_PREFIX = "0x";

    /// <summary>
    /// 执行扫描。
    /// </summary>
    /// <param name="action">操作类型: pattern、value、filter、list、drop。</param>
    /// <param name="pattern">特征码文本，支持 ?? 通配。</param>
    /// <param name="valueType">值类型名，value 模式需要；支持 byte、sbyte、short、ushort、int、uint、long、ulong、float、double、bool，也接受 u8、i8、u16、i16、u32、i32、u64、i64、f32、f64 这类别名。</param>
    /// <param name="value">目标值，filter 模式下作为 equals 或 between 的下界。</param>
    /// <param name="upper">between 过滤的上界。</param>
    /// <param name="session">会话 id。</param>
    /// <param name="filter">过滤条件: changed、unchanged、increased、decreased、equals、between。</param>
    /// <param name="module">限定模块名，省略时使用主模块。</param>
    /// <param name="whole">是否扫描整个可读地址空间。</param>
    /// <param name="rangeStart">扫描范围起点。</param>
    /// <param name="rangeEnd">扫描范围终点。</param>
    /// <param name="alignment">对齐步长，0 表示按类型自然对齐。</param>
    /// <param name="limit">返回的候选地址数量上限。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? pattern    = null,
        string? valueType  = null,
        string? value      = null,
        string? upper      = null,
        string? session    = null,
        string? filter     = null,
        string? module     = null,
        bool    whole      = false,
        string? rangeStart = null,
        string? rangeEnd   = null,
        int     alignment  = 0,
        int     limit      = 16
    )
    {
        var page = Math.Clamp(limit, 1, 500);
        var from = ParseOptionalAddress(rangeStart);
        var to   = ParseOptionalAddress(rangeEnd);

        return action.ToLowerInvariant() switch
        {
            "pattern" => ScanPattern(pattern, module, whole, from, to, page),
            "value"   => StartSession(valueType, value, upper, module, whole, from, to, alignment, page),
            "filter"  => FilterSession(session, filter, value, upper, page),
            "list"    => ListSessions(),
            "drop"    => DropSession(session),
            _         => throw new McpException($"不支持的操作 \"{action}\"，可用值为 pattern、value、filter、list、drop。")
        };
    }

    private static string ScanPattern
    (
        string? pattern,
        string? module,
        bool    whole,
        nint    rangeStart,
        nint    rangeEnd,
        int     limit
    )
    {
        if (string.IsNullOrWhiteSpace(pattern))
            throw new McpException("pattern 模式需要提供 pattern。");

        var started = Stopwatch.GetTimestamp();
        var regions = RegionProvider.GetReadableRegions(whole, module, rangeStart, rangeEnd);
        var hits    = MemoryScanner.ScanPattern(pattern, regions, limit);
        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

        MCPRuntime.Trace.Write("mem_scan", $"pattern={pattern} hits={hits.Count} regions={regions.Count}", elapsed);

        var builder = new StringBuilder(1024);
        builder.Append("{\"action\":\"pattern\",\"hits\":").Append(hits.Count);
        builder.Append(",\"regions\":").Append(regions.Count);
        builder.Append(",\"addresses\":[");

        for (var index = 0; index < hits.Count; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append('{');
            builder.Append("\"address\":").Append(ValueFormatter.Format(MemoryScanner.FormatAddress(hits[index]),     0));
            builder.Append(",\"ref\":").Append(ValueFormatter.Format(MCPRuntime.References.TrackPointer(hits[index]), 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string StartSession
    (
        string? valueType,
        string? value,
        string? upper,
        string? module,
        bool    whole,
        nint    rangeStart,
        nint    rangeEnd,
        int     alignment,
        int     limit
    )
    {
        if (string.IsNullOrWhiteSpace(valueType))
            throw new McpException("value 模式需要提供 valueType。");

        if (string.IsNullOrWhiteSpace(value))
            throw new McpException("value 模式需要提供 value。");

        var lower      = ParseNumber(value);
        var upperBound = string.IsNullOrWhiteSpace(upper) ? (double?)null : ParseNumber(upper);

        var started = Stopwatch.GetTimestamp();
        var regions = RegionProvider.GetReadableRegions(whole, module, rangeStart, rangeEnd);
        var (candidates, values, total, truncated) = MemoryScanner.ScanValue(valueType, lower, upperBound, regions, alignment);
        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

        var id          = MCPRuntime.NextScanSessionId();
        var scanSession = new ScanSession(id, valueType, candidates, values, total) { Truncated = truncated };
        MCPRuntime.ScanSessions[id] = scanSession;

        MCPRuntime.Trace.Write("mem_scan", $"value session={id} type={valueType} total={total} kept={candidates.Count}", elapsed);

        return RenderSession(scanSession, limit, "value");
    }

    private static string FilterSession
    (
        string? id,
        string? filter,
        string? value,
        string? upper,
        int     limit
    )
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new McpException("filter 模式需要提供 session。");

        if (string.IsNullOrWhiteSpace(filter))
            throw new McpException("filter 模式需要提供 filter。");

        if (!MCPRuntime.ScanSessions.TryGetValue(id, out var scanSession) || scanSession is null)
            throw new McpException($"会话 \"{id}\" 不存在或已释放。");

        var target     = string.IsNullOrWhiteSpace(value) ? (double?)null : ParseNumber(value);
        var upperBound = string.IsNullOrWhiteSpace(upper) ? (double?)null : ParseNumber(upper);

        var started = Stopwatch.GetTimestamp();
        MemoryScanner.ApplyFilter(scanSession, filter, target, upperBound);
        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

        MCPRuntime.Trace.Write("mem_scan", $"filter session={id} filter={filter} kept={scanSession.Candidates.Count}", elapsed);

        return RenderSession(scanSession, limit, "filter");
    }

    private static string ListSessions()
    {
        var builder = new StringBuilder(512);
        builder.Append("{\"action\":\"list\",\"sessions\":[");

        var entries = MCPRuntime.ScanSessions.Values.OrderBy(item => item.Id, StringComparer.Ordinal).ToArray();

        for (var index = 0; index < entries.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var entry = entries[index];
            builder.Append('{');
            builder.Append("\"id\":").Append(ValueFormatter.Format(entry.Id,                0));
            builder.Append(",\"valueType\":").Append(ValueFormatter.Format(entry.ValueType, 0));
            builder.Append(",\"remaining\":").Append(entry.Candidates.Count);
            builder.Append(",\"totalMatched\":").Append(entry.TotalMatched);
            builder.Append(",\"createdAt\":").Append
            (
                ValueFormatter.Format
                (
                    entry.CreatedAt.ToString("O", CultureInfo.InvariantCulture),
                    0
                )
            );
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string DropSession
    (
        string? id
    )
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new McpException("drop 模式需要提供 session。");

        var removed = MCPRuntime.ScanSessions.TryRemove(id, out _);
        return "{\"action\":\"drop\",\"removed\":" + (removed ? "true" : "false") + "}";
    }

    private static string RenderSession
    (
        ScanSession scanSession,
        int         limit,
        string      action
    )
    {
        var builder = new StringBuilder(1024);
        builder.Append("{\"action\":").Append(ValueFormatter.Format(action,                   0));
        builder.Append(",\"session\":").Append(ValueFormatter.Format(scanSession.Id,          0));
        builder.Append(",\"valueType\":").Append(ValueFormatter.Format(scanSession.ValueType, 0));
        builder.Append(",\"remaining\":").Append(scanSession.Candidates.Count);
        builder.Append(",\"totalMatched\":").Append(scanSession.TotalMatched);
        builder.Append(",\"truncated\":").Append(scanSession.Truncated ? "true" : "false");
        builder.Append(",\"candidates\":[");

        var count = Math.Min(limit, scanSession.Candidates.Count);

        for (var index = 0; index < count; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append('{');
            builder.Append("\"address\":").Append
            (
                ValueFormatter.Format
                (
                    MemoryScanner.FormatAddress(scanSession.Candidates[index]),
                    0
                )
            );
            builder.Append(",\"value\":").Append(ValueFormatter.Format(scanSession.Values[index], 0));
            builder.Append(",\"ref\":").Append
            (
                ValueFormatter.Format
                (
                    MCPRuntime.References.TrackPointer(scanSession.Candidates[index]),
                    0
                )
            );
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static nint ParseOptionalAddress
    (
        string? text
    ) =>
        string.IsNullOrWhiteSpace(text) ? 0 : (nint)MemoryAccess.ParseAddress(text);

    private static double ParseNumber
    (
        string text
    )
    {
        var trimmed = text.Trim();

        if (trimmed.StartsWith(HEX_PREFIX, StringComparison.OrdinalIgnoreCase))
            return MemoryAccess.ParseAddress(trimmed);

        return double.Parse(trimmed, CultureInfo.InvariantCulture);
    }
}
