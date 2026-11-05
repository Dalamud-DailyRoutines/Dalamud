using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using Dalamud.Memory;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 在给定区域上做特征码扫描与数值扫描。
/// </summary>
internal static class MemoryScanner
{
    private const int BLOCK_SIZE     = 0x10000;
    private const int MAX_CANDIDATES = 2_000_000;

    /// <summary>
    /// 按特征码扫描。
    /// </summary>
    /// <param name="pattern">特征码文本，支持 <c>??</c> 通配。</param>
    /// <param name="regions">扫描区域。</param>
    /// <param name="limit">命中数量上限。</param>
    /// <param name="cancellationToken">取消尚未执行的操作或异步等待。</param>
    /// <returns>命中地址。</returns>
    public static List<nint> ScanPattern
    (
        string                      pattern,
        IReadOnlyList<MemoryRegion> regions,
        int                         limit,
        CancellationToken           cancellationToken = default
    )
    {
        var (bytes, wildcard) = ParsePattern(pattern);
        var results = new List<nint>();

        if (bytes.Length == 0)
            throw new McpException("特征码为空。");

        foreach (var region in regions)
        {
            var overlap = (ulong)bytes.Length;

            for (ulong offset = 0; offset < region.Size; offset += BLOCK_SIZE)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remaining = region.Size - offset;
                var wanted    = BLOCK_SIZE  + overlap;
                var chunkLength = (int)(remaining < wanted ?
                                            remaining :
                                            wanted);
                if (chunkLength < bytes.Length)
                    break;

                var buffer = ReadBlock((nint)(region.Start + offset), chunkLength);

                for (var index = 0; index < BLOCK_SIZE && index + bytes.Length <= buffer.Length; index++)
                {
                    if (!Matches(buffer, index, bytes, wildcard))
                        continue;

                    results.Add((nint)(region.Start + offset + (ulong)index));
                    if (results.Count >= limit)
                        return results;
                }
            }
        }

        return results;
    }

    /// <summary>
    /// 做一次数值扫描，返回候选与对应数值。
    /// </summary>
    /// <param name="valueType">值类型名。</param>
    /// <param name="lower">下界。</param>
    /// <param name="upper">上界，省略时按精确值处理。</param>
    /// <param name="regions">扫描区域。</param>
    /// <param name="alignment">对齐步长，0 表示按类型自然对齐。</param>
    /// <param name="cancellationToken">取消尚未执行的操作或异步等待。</param>
    /// <returns>候选地址、对应数值、命中总数与截断标记。</returns>
    public static MemoryScanResult ScanValue
    (
        string                      valueType,
        NumericValue                lower,
        NumericValue?               upper,
        IReadOnlyList<MemoryRegion> regions,
        int                         alignment,
        CancellationToken           cancellationToken = default
    )
    {
        var size = GetValueSize(valueType);
        var step = alignment > 0 ?
                       alignment :
                       size;

        var candidates = new List<nint>();
        var values     = new List<NumericValue>();
        var total      = 0;

        foreach (var region in regions)
        {
            for (ulong offset = 0; offset < region.Size; offset += BLOCK_SIZE)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remaining = region.Size - offset;
                var wanted    = BLOCK_SIZE  + (ulong)size;
                var chunkLength = (int)(remaining < wanted ?
                                            remaining :
                                            wanted);
                if (chunkLength < size)
                    break;

                var buffer = ReadBlock((nint)(region.Start + offset), chunkLength);

                for (var index = 0; index < BLOCK_SIZE && index + size <= buffer.Length; index += step)
                {
                    var numeric = ReadNumeric(buffer, index, valueType);
                    if (!InRange(numeric, lower, upper))
                        continue;

                    total++;

                    if (candidates.Count >= MAX_CANDIDATES)
                        return new MemoryScanResult(candidates, values, total, true);

                    candidates.Add((nint)(region.Start + offset + (ulong)index));
                    values.Add(numeric);
                }
            }
        }

        return new MemoryScanResult(candidates, values, total, false);
    }

    /// <summary>
    /// 对会话施加一次过滤。
    /// </summary>
    /// <param name="session">目标会话。</param>
    /// <param name="filter">过滤条件。</param>
    /// <param name="target">equals 或 between 的目标值。</param>
    /// <param name="upper">between 的上界。</param>
    /// <param name="cancellationToken">取消尚未完成的扫描。</param>
    public static void ApplyFilter
    (
        ScanSession       session,
        string            filter,
        NumericValue?     target,
        NumericValue?     upper,
        CancellationToken cancellationToken = default
    )
    {
        var kept       = new List<nint>();
        var keptValues = new List<NumericValue>();
        var normalized = filter.ToLowerInvariant();

        for (var index = 0; index < session.Candidates.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var address  = session.Candidates[index];
            var previous = session.Values[index];
            var current  = ReadNumericAt(address, session.ValueType);

            var keep = normalized switch
            {
                "changed"   => current != previous,
                "unchanged" => current == previous,
                "increased" => current > previous,
                "decreased" => current < previous,
                "equals"    => target.HasValue && current                   == target.Value,
                "between"   => target.HasValue && upper.HasValue && current >= target.Value && current <= upper.Value,
                _           => throw new McpException($"不支持的过滤条件 \"{filter}\"，可用值为 changed、unchanged、increased、decreased、equals、between。")
            };

            if (!keep)
                continue;

            kept.Add(address);
            keptValues.Add(current);
        }

        session.Candidates.Clear();
        session.Candidates.AddRange(kept);
        session.Values.Clear();
        session.Values.AddRange(keptValues);
    }

    /// <summary>
    /// 取回值类型的字节大小。
    /// </summary>
    /// <param name="valueType">值类型名。</param>
    /// <returns>字节大小。</returns>
    public static int GetValueSize
    (
        string valueType
    ) => valueType.ToLowerInvariant() switch
    {
        "byte" or "u8" or "uint8"     => 1,
        "sbyte" or "i8" or "int8"     => 1,
        "short" or "i16" or "int16"   => 2,
        "ushort" or "u16" or "uint16" => 2,
        "int" or "i32" or "int32"     => 4,
        "uint" or "u32" or "uint32"   => 4,
        "float" or "f32" or "single"  => 4,
        "long" or "i64" or "int64"    => 8,
        "ulong" or "u64" or "uint64"  => 8,
        "double" or "f64"             => 8,
        "bool"                        => 1,
        _                             => throw new McpException($"不支持的值类型 \"{valueType}\"。")
    };

    /// <summary>
    /// 从内存中按类型读出一个数值。
    /// </summary>
    /// <param name="address">地址。</param>
    /// <param name="valueType">值类型名。</param>
    /// <returns>数值。</returns>
    public static NumericValue ReadNumericAt
    (
        nint   address,
        string valueType
    )
    {
        var size   = GetValueSize(valueType);
        var buffer = MemoryAccess.ReadBytes(address, size);
        return ReadNumeric(buffer, 0, valueType);
    }

    /// <summary>
    /// 把地址渲染成 0x 前缀文本。
    /// </summary>
    /// <param name="address">地址。</param>
    /// <returns>地址文本。</returns>
    public static string FormatAddress
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);

    private static (byte[] Bytes, bool[] Wildcard) ParsePattern
    (
        string pattern
    )
    {
        var cleaned = pattern.Replace(" ", string.Empty, StringComparison.Ordinal)
                             .Replace("-", string.Empty, StringComparison.Ordinal);

        if (cleaned.Length % 2 != 0)
            throw new McpException("特征码长度必须是偶数个十六进制字符。");

        var count    = cleaned.Length / 2;
        var bytes    = new byte[count];
        var wildcard = new bool[count];

        for (var index = 0; index < count; index++)
        {
            var pair = cleaned.Substring(index * 2, 2);

            if (pair == "??")
            {
                wildcard[index] = true;
                continue;
            }

            bytes[index] = byte.Parse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return (bytes, wildcard);
    }

    private static bool Matches
    (
        byte[] buffer,
        int    offset,
        byte[] bytes,
        bool[] wildcard
    )
    {
        for (var index = 0; index < bytes.Length; index++)
        {
            if (wildcard[index])
                continue;

            if (buffer[offset + index] != bytes[index])
                return false;
        }

        return true;
    }

    private static byte[] ReadBlock
    (
        nint address,
        int  length
    )
    {
        try
        {
            return MemoryAccess.ReadBytes(address, length);
        }
        catch (Exception exception)
        {
            throw new McpException($"读取 {FormatAddress(address)} 处的 {length} 字节失败: {exception.Message}");
        }
    }

    private static NumericValue ReadNumeric
    (
        byte[] buffer,
        int    offset,
        string valueType
    )
    {
        var span = buffer.AsSpan(offset);

        return valueType.ToLowerInvariant() switch
        {
            "byte" or "u8" or "uint8"     => NumericValue.FromInteger(span[0]),
            "sbyte" or "i8" or "int8"     => NumericValue.FromInteger((sbyte)span[0]),
            "short" or "i16" or "int16"   => NumericValue.FromInteger(BinaryPrimitives.ReadInt16LittleEndian(span)),
            "ushort" or "u16" or "uint16" => NumericValue.FromInteger(BinaryPrimitives.ReadUInt16LittleEndian(span)),
            "int" or "i32" or "int32"     => NumericValue.FromInteger(BinaryPrimitives.ReadInt32LittleEndian(span)),
            "uint" or "u32" or "uint32"   => NumericValue.FromInteger(BinaryPrimitives.ReadUInt32LittleEndian(span)),
            "float" or "f32" or "single"  => NumericValue.FromFloat(BinaryPrimitives.ReadSingleLittleEndian(span)),
            "long" or "i64" or "int64"    => NumericValue.FromInteger(BinaryPrimitives.ReadInt64LittleEndian(span)),
            "ulong" or "u64" or "uint64"  => NumericValue.FromInteger(BinaryPrimitives.ReadUInt64LittleEndian(span)),
            "double" or "f64"             => NumericValue.FromFloat(BinaryPrimitives.ReadDoubleLittleEndian(span)),
            "bool" => NumericValue.FromInteger
            (
                span[0] != 0 ?
                    1 :
                    0
            ),
            _ => throw new McpException($"不支持的值类型 \"{valueType}\"。")
        };
    }

    private static bool InRange(NumericValue value, NumericValue lower, NumericValue? upper) =>
        upper.HasValue ?
            value >= lower && value <= upper.Value :
            value == lower;
}
