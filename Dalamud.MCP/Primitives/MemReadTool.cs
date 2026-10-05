using System.Diagnostics;
using System.Globalization;

namespace Dalamud;

/// <summary>
/// <c>mem_read</c> 原语：读取原生内存，支持原始转储与按类型元数据的结构化读取。
/// </summary>
internal static class MemReadTool
{
    /// <summary>
    /// 执行读取。
    /// </summary>
    /// <param name="address">起始地址，支持十进制或 0x 前缀十六进制。</param>
    /// <param name="length">原始读取的字节数。</param>
    /// <param name="type">结构化读取时的类型全名或简单名。</param>
    /// <param name="path">结构化读取时的字段路径。</param>
    /// <param name="depth">结构化展开层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  address,
        int     length = 64,
        string? type   = null,
        string? path   = null,
        int     depth  = 1
    )
    {
        var baseAddress = (nint)MemoryAccess.ParseAddress(address);
        var started     = Stopwatch.GetTimestamp();

        string result;

        if (string.IsNullOrWhiteSpace(type))
        {
            var dump = MemoryAccess.ReadRaw(baseAddress, length);
            result = "{\"address\":"                                      +
                     ValueFormatter.Format(FormatAddress(baseAddress), 0) +
                     ",\"length\":"                                       +
                     length                                               +
                     ",\"dump\":"                                         +
                     ValueFormatter.Format(dump, 0)                       +
                     "}";
        }
        else
        {
            var resolvedType = StructureLayout.FindType(type);
            var (target, targetType, elementCount) = StructuredReader.Resolve(baseAddress, resolvedType, MemberPath.Parse(path));

            result = "{\"address\":"                                                  +
                     ValueFormatter.Format(FormatAddress(target), 0)                  +
                     ",\"type\":"                                                     +
                     ValueFormatter.Format(targetType.FullName ?? targetType.Name, 0) +
                     ",\"value\":"                                                    +
                     (elementCount is { } count
                          ? count.ToString(CultureInfo.InvariantCulture)
                          : StructuredReader.Render(target, targetType, depth))       +
                     "}";
        }

        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        MCPRuntime.Trace.Write("mem_read", $"{address} length={length} type={type} path={path}", elapsed);
        return result;
    }

    private static string FormatAddress
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);
}
