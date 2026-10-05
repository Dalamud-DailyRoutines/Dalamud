using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 对原生内存做原始与按类型的读写。
/// </summary>
internal static unsafe class MemoryAccess
{
    private const int BYTES_PER_ROW = 16;

    /// <summary>
    /// 读取一段原始字节并渲染成十六进制转储文本。
    /// </summary>
    /// <param name="address">起始地址。</param>
    /// <param name="length">字节数。</param>
    /// <returns>十六进制转储文本。</returns>
    public static string ReadRaw
    (
        nint address,
        int  length
    )
    {
        var bytes = ReadBytes(address, length);

        var builder = new StringBuilder(bytes.Length * 4);

        for (var row = 0; row < bytes.Length; row += BYTES_PER_ROW)
        {
            builder.Append(((long)address + row).ToString("x16", CultureInfo.InvariantCulture)).Append("  ");

            var rowLength = Math.Min(BYTES_PER_ROW, bytes.Length - row);

            for (var column = 0; column < BYTES_PER_ROW; column++)
            {
                builder.Append
                (
                    column < rowLength
                        ? bytes[row + column].ToString("x2", CultureInfo.InvariantCulture) + " "
                        : "   "
                );
            }

            builder.Append(' ');

            for (var column = 0; column < rowLength; column++)
            {
                var value = bytes[row + column];
                builder.Append(value is >= 32 and < 127 ? (char)value : '.');
            }

            builder.Append('\n');
        }

        return builder.ToString();
    }

    /// <summary>
    /// 读取一段原始字节。
    /// </summary>
    /// <param name="address">起始地址。</param>
    /// <param name="length">字节数。</param>
    /// <returns>字节序列。</returns>
    public static byte[] ReadBytes
    (
        nint address,
        int  length
    )
    {
        if (address == 0)
            throw new McpException("地址为 0。");

        if (length is <= 0 or > 1024 * 1024)
            throw new McpException($"长度 {length} 超出允许范围 (1..1048576)。");

        if (!IsRangeReadable(address, length))
            throw new McpException($"地址 0x{(long)address:x} 起的 {length} 字节不可读，已拒绝访问。");

        var result = new byte[length];
        Marshal.Copy(address, result, 0, length);
        return result;
    }

    /// <summary>
    /// 写入一段原始字节。
    /// </summary>
    /// <param name="address">起始地址。</param>
    /// <param name="bytes">字节序列。</param>
    public static void WriteBytes
    (
        nint   address,
        byte[] bytes
    )
    {
        if (address == 0)
            throw new McpException("地址为 0。");

        if (bytes.Length == 0)
            throw new McpException("写入内容为空。");

        if (!IsRangeWritable(address, bytes.Length))
            throw new McpException($"地址 0x{(long)address:x} 起的 {bytes.Length} 字节不可写，已拒绝访问。");

        Marshal.Copy(bytes, 0, address, bytes.Length);
    }

    /// <summary>
    /// 判断一段地址区间是否可读。
    /// </summary>
    /// <param name="address">起始地址。</param>
    /// <param name="length">字节数。</param>
    /// <returns>整段是否可读。</returns>
    public static bool IsRangeReadable
    (
        nint address,
        long length
    ) => IsRangeAccessible
    (
        address,
        length,
        NativeApi.PAGE_READONLY     |
        NativeApi.PAGE_READWRITE    |
        NativeApi.PAGE_EXECUTE_READ |
        NativeApi.PAGE_EXECUTE_READWRITE
    );

    /// <summary>
    /// 判断一段地址区间是否可写。
    /// </summary>
    /// <param name="address">起始地址。</param>
    /// <param name="length">字节数。</param>
    /// <returns>整段是否可写。</returns>
    public static bool IsRangeWritable
    (
        nint address,
        long length
    ) => IsRangeAccessible(address, length, NativeApi.PAGE_READWRITE | NativeApi.PAGE_EXECUTE_READWRITE);

    private static bool IsRangeAccessible
    (
        nint address,
        long length,
        uint allowed
    )
    {
        if (address == 0 || length <= 0)
            return false;

        var current = (ulong)address;
        var end     = current + (ulong)length;

        while (current < end)
        {
            if (NativeApi.VirtualQuery((nint)(long)current, out var info, (nuint)sizeof(NativeApi.MemoryBasicInformation)) == 0)
                return false;

            if (info.State != NativeApi.MEM_COMMIT || (info.Protect & NativeApi.PAGE_GUARD) != 0)
                return false;

            if ((info.Protect & allowed) == 0)
                return false;

            var regionEnd = (ulong)info.BaseAddress + info.RegionSize;
            if (regionEnd <= current)
                return false;

            current = regionEnd;
        }

        return true;
    }

    /// <summary>
    /// 按类型读取一个标量值。
    /// </summary>
    /// <param name="address">值的地址。</param>
    /// <param name="type">值类型。</param>
    /// <returns>读到的值。</returns>
    public static object? ReadValue
    (
        nint address,
        Type type
    )
    {
        if (address == 0)
            throw new McpException("地址为 0。");

        var size = type.IsPointer || type == typeof(nint) || type == typeof(IntPtr) || type == typeof(nuint) || type == typeof(UIntPtr)
                       ? IntPtr.Size
                       : StructureLayout.GetSize(type);

        if (size <= 0)
            throw new McpException($"无法确定 {type.Name} 的大小。");

        if (!IsRangeReadable(address, size))
            throw new McpException($"地址 0x{(long)address:x} 起的 {size} 字节不可读。");

        if (type.IsEnum)
            return Enum.ToObject(type, ReadValue(address, Enum.GetUnderlyingType(type))!);

        if (type.IsPointer || type == typeof(nint) || type == typeof(IntPtr))
            return *(nint*)address;

        if (type == typeof(nuint) || type == typeof(UIntPtr))
            return *(nuint*)address;

        if (type == typeof(byte))
            return *(byte*)address;

        if (type == typeof(sbyte))
            return *(sbyte*)address;

        if (type == typeof(short))
            return *(short*)address;

        if (type == typeof(ushort))
            return *(ushort*)address;

        if (type == typeof(int))
            return *(int*)address;

        if (type == typeof(uint))
            return *(uint*)address;

        if (type == typeof(long))
            return *(long*)address;

        if (type == typeof(ulong))
            return *(ulong*)address;

        if (type == typeof(float))
            return *(float*)address;

        if (type == typeof(double))
            return *(double*)address;

        if (type == typeof(bool))
            return *(byte*)address != 0;

        if (type == typeof(char))
            return *(char*)address;

        return type.IsValueType
                   ? Marshal.PtrToStructure(address, type)
                   : throw new McpException($"暂不支持读取类型 {type.Name}。");
    }

    /// <summary>
    /// 按类型写入一个标量值。
    /// </summary>
    /// <param name="address">值的地址。</param>
    /// <param name="type">值类型。</param>
    /// <param name="raw">以文本或十六进制给出的新值。</param>
    public static void WriteValue
    (
        nint   address,
        Type   type,
        string raw
    )
    {
        if (address == 0)
            throw new McpException("地址为 0。");

        var size = type.IsPointer || type == typeof(nint) || type == typeof(IntPtr) || type == typeof(nuint) || type == typeof(UIntPtr)
                       ? IntPtr.Size
                       : StructureLayout.GetSize(type);

        if (size <= 0)
            throw new McpException($"无法确定 {type.Name} 的大小。");

        if (!IsRangeWritable(address, size))
            throw new McpException($"地址 0x{(long)address:x} 起的 {size} 字节不可写。");

        if (type.IsEnum)
        {
            WriteValue(address, Enum.GetUnderlyingType(type), raw);
            return;
        }

        if (type.IsPointer || type == typeof(nint) || type == typeof(IntPtr))
        {
            *(nint*)address = (nint)ParseAddress(raw);
            return;
        }

        if (type == typeof(nuint) || type == typeof(UIntPtr))
        {
            *(nuint*)address = (nuint)ParseAddress(raw);
            return;
        }

        if (type == typeof(byte))
            *(byte*)address = byte.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(sbyte))
            *(sbyte*)address = sbyte.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(short))
            *(short*)address = short.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(ushort))
            *(ushort*)address = ushort.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(int))
            *(int*)address = int.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(uint))
            *(uint*)address = uint.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(long))
            *(long*)address = long.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(ulong))
            *(ulong*)address = ulong.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(float))
            *(float*)address = float.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(double))
            *(double*)address = double.Parse(raw, CultureInfo.InvariantCulture);
        else if (type == typeof(bool))
            *(byte*)address = bool.Parse(raw) ? (byte)1 : (byte)0;
        else if (type == typeof(char))
            *(char*)address = raw.Length > 0 ? raw[0] : throw new McpException("无法把空字符串转换为 char。");
        else
            throw new McpException($"暂不支持写入类型 {type.Name}。");
    }

    /// <summary>
    /// 解析文本形式给出的地址。
    /// </summary>
    /// <param name="raw">十进制或 0x 开头的十六进制文本。</param>
    /// <returns>地址。</returns>
    public static long ParseAddress
    (
        string raw
    )
    {
        var text = raw.Trim();

        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                   ? long.Parse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                   : long.Parse(text,      NumberStyles.Integer,   CultureInfo.InvariantCulture);
    }
}
