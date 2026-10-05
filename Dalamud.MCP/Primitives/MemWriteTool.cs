using System.Diagnostics;
using System.Globalization;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>mem_write</c> 原语：写入原生内存，支持原始字节与按类型元数据的字段写入。
/// </summary>
internal static class MemWriteTool
{
    /// <summary>
    /// 执行写入。
    /// </summary>
    /// <param name="address">起始地址，支持十进制或 0x 前缀十六进制。</param>
    /// <param name="hex">要写入的原始字节，以十六进制文本给出，可含空格或短横线。</param>
    /// <param name="type">结构化写入时的类型全名或简单名。</param>
    /// <param name="path">结构化写入时的字段路径，最后一段为目标字段。</param>
    /// <param name="value">结构化写入时以文本给出的新值。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  address,
        string? hex   = null,
        string? type  = null,
        string? path  = null,
        string? value = null
    )
    {
        var baseAddress = (nint)MemoryAccess.ParseAddress(address);
        var started     = Stopwatch.GetTimestamp();

        string result;

        if (!string.IsNullOrWhiteSpace(hex))
        {
            var bytes = ParseHexBytes(hex);
            MemoryAccess.WriteBytes(baseAddress, bytes);

            result = "{\"address\":" + ValueFormatter.Format(FormatAddress(baseAddress), 0) + ",\"written\":" + bytes.Length + "}";
        }
        else
        {
            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(path) || value is null)
                throw new McpException("结构化写入需要同时提供 type、path 与 value。");

            var resolvedType = StructureLayout.FindType(type);
            var segments     = MemberPath.Parse(path);
            if (segments.Length == 0)
                throw new McpException("结构化写入的 path 不能为空。");

            var (target, targetType, elementCount) = StructuredReader.Resolve(baseAddress, resolvedType, segments);

            if (elementCount is not null)
                throw new McpException("目标路径指向内联数组的元素个数，只能读取不能写入。");

            MemoryAccess.WriteValue(target, targetType, value);

            result = "{\"address\":"                                                  +
                     ValueFormatter.Format(FormatAddress(target), 0)                  +
                     ",\"type\":"                                                     +
                     ValueFormatter.Format(targetType.FullName ?? targetType.Name, 0) +
                     ",\"value\":"                                                    +
                     ValueFormatter.Format(value, 0)                                  +
                     "}";
        }

        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        MCPRuntime.Trace.Write("mem_write", $"{address} hex={hex} type={type} path={path} value={value}", elapsed);
        return result;
    }

    private static byte[] ParseHexBytes
    (
        string hex
    )
    {
        var cleaned = hex.Replace(" ", string.Empty, StringComparison.Ordinal)
                         .Replace("-", string.Empty, StringComparison.Ordinal);

        if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            cleaned = cleaned[2..];

        if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
            throw new McpException("十六进制文本长度必须是非零偶数。");

        var bytes = new byte[cleaned.Length / 2];

        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = byte.Parse
            (
                cleaned.AsSpan(index * 2, 2),
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture
            );
        }

        return bytes;
    }

    private static string FormatAddress
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);
}
