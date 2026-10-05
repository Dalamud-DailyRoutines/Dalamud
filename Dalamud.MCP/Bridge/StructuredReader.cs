using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using FFXIVClientStructs.FFXIV.Client.System.String;
using InteropGenerator.Runtime;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 按类型元数据沿字段路径在原生内存中定位并渲染结构，支持内联数组下标与原生字符串。
/// </summary>
internal static unsafe class StructuredReader
{
    private const int MAX_FIELDS_PER_LEVEL = 128;

    /// <summary>
    /// 沿字段路径求值。最后一段若是指针类型，返回指针值本身而不解引用。
    /// </summary>
    /// <param name="baseAddress">结构起点。</param>
    /// <param name="type">起点类型。</param>
    /// <param name="segments">字段路径段。</param>
    /// <returns>最终地址、该处类型，以及内联数组元素个数（仅当路径指向元素个数时非空）。</returns>
    public static (nint Address, Type Type, int? ElementCount) Resolve
    (
        nint     baseAddress,
        Type     type,
        string[] segments
    )
    {
        var address     = baseAddress;
        var currentType = type;

        for (var index = 0; index < segments.Length; index++)
        {
            var segment = segments[index];
            var isLast  = index == segments.Length - 1;

            if (StructureLayout.TryGetInlineArray(currentType) is { } inlineArray)
            {
                if (string.Equals(segment, "Length", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(segment, "Count",  StringComparison.OrdinalIgnoreCase))
                {
                    if (!isLast)
                        throw new McpException($"\"{segment}\" 是内联数组的元素个数，后面不能再接路径段。");

                    return (address, typeof(int), inlineArray.Count);
                }

                if (!int.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var elementIndex))
                    throw new McpException($"{currentType.Name} 是内联数组，路径段需要是下标或 Length，当前为 \"{segment}\"。");

                if (elementIndex < 0 || elementIndex >= inlineArray.Count)
                    throw new McpException($"内联数组下标 {elementIndex} 越界，元素个数为 {inlineArray.Count}。");

                var elementSize = StructureLayout.GetSize(inlineArray.ElementType);
                if (elementSize <= 0)
                    throw new McpException($"无法确定 {inlineArray.ElementType.Name} 的大小，不能按下标寻址。");

                address     += elementIndex * elementSize;
                currentType =  inlineArray.ElementType;
                continue;
            }

            var field = StructureLayout.FindField(currentType, segment);
            address     += field.Offset;
            currentType =  field.FieldType;

            if (isLast || !currentType.IsPointer)
                continue;

            address = MemoryAccess.ReadValue(address, currentType) is nint pointer ? pointer : 0;
            if (address == 0)
                throw new McpException($"路径段 \"{segment}\" 指向空指针。");

            currentType = currentType.GetElementType()!;
        }

        return (address, currentType, null);
    }

    /// <summary>
    /// 渲染结构或标量。
    /// </summary>
    /// <param name="address">目标地址。</param>
    /// <param name="type">目标类型。</param>
    /// <param name="depth">嵌套展开层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Render
    (
        nint address,
        Type type,
        int  depth
    )
    {
        var builder = new StringBuilder(512);
        WriteValue(builder, address, type, depth, []);
        return builder.ToString();
    }

    private static void WriteValue
    (
        StringBuilder      builder,
        nint               address,
        Type               type,
        int                depth,
        HashSet<nint> visited
    )
    {
        if (StructureLayout.IsScalar(type))
        {
            builder.Append(ValueFormatter.Format(MemoryAccess.ReadValue(address, type), 0));
            return;
        }

        if (TryWriteString(builder, address, type))
            return;

        if (StructureLayout.TryGetInlineArray(type) is { } inlineArray)
        {
            builder.Append("{\"__type__\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
            builder.Append(",\"__address__\":\"").Append(FormatAddress(address)).Append('"');
            builder.Append(",\"__count__\":").Append(inlineArray.Count);

            if (depth <= 0)
            {
                builder.Append('}');
                return;
            }

            var itemSize = StructureLayout.GetSize(inlineArray.ElementType);
            if (itemSize <= 0)
            {
                builder.Append(",\"__error__\":").Append(ValueFormatter.Format($"无法确定 {inlineArray.ElementType.Name} 的大小。", 0));
                builder.Append('}');
                return;
            }

            var itemCount = Math.Min(inlineArray.Count, MAX_FIELDS_PER_LEVEL);

            builder.Append(",\"__shown__\":").Append(itemCount);
            builder.Append(",\"items\":[");

            for (var index = 0; index < itemCount; index++)
            {
                if (index > 0)
                    builder.Append(',');

                WriteValue(builder, address + (index * itemSize), inlineArray.ElementType, depth - 1, visited);
            }

            builder.Append("]}");
            return;
        }

        if (depth <= 0)
        {
            builder.Append("{\"__type__\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0))
                   .Append(",\"__address__\":\"").Append(FormatAddress(address)).Append("\"}");
            return;
        }

        if (!visited.Add(address))
        {
            builder.Append("{\"__type__\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0))
                   .Append(",\"__loop__\":\"0x").Append(FormatAddress(address)).Append("\"}");
            return;
        }

        var fields = StructureLayout.GetFields(type);

        builder.Append("{\"__type__\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
        builder.Append(",\"__address__\":\"").Append(FormatAddress(address)).Append('"');

        var typeSize = StructureLayout.GetSize(type);
        builder.Append(",\"__size__\":").Append(typeSize < 0 ? "null" : typeSize.ToString(CultureInfo.InvariantCulture));
        builder.Append(",\"fields\":{");

        var written   = 0;
        var truncated = false;

        foreach (var field in fields)
        {
            if (written >= MAX_FIELDS_PER_LEVEL)
            {
                truncated = true;
                break;
            }

            if (written > 0)
                builder.Append(',');

            builder.Append(ValueFormatter.Format(field.Name, 0)).Append(':');
            WriteValue(builder, address + field.Offset, field.FieldType, depth - 1, visited);
            written++;
        }

        if (truncated)
            builder.Append(",\"__truncated__\":true");

        builder.Append("}}");
        visited.Remove(address);
    }

    private static bool TryWriteString
    (
        StringBuilder builder,
        nint          address,
        Type          type
    )
    {
        if (type == typeof(CStringPointer))
        {
            builder.Append(ValueFormatter.Format(ReadUtf8(*(byte**)address, null), 0));
            return true;
        }

        if (type != typeof(Utf8String))
            return false;

        var inlineFlagField = StructureLayout.FindField(type, "IsUsingInlineBuffer");
        var lengthField     = StructureLayout.FindField(type, "StringLength");
        var bufferField     = StructureLayout.FindField(type, "_inlineBuffer");

        var length      = (int)*(long*)(address + lengthField.Offset);
        var useInline   = *(byte*)(address + inlineFlagField.Offset) != 0;
        var textPointer = useInline
                              ? (byte*)(address + bufferField.Offset)
                              : *(byte**)(address + StructureLayout.FindField(type, "StringPtr").Offset);

        builder.Append(ValueFormatter.Format(ReadUtf8(textPointer, length), 0));
        return true;
    }

    private static string? ReadUtf8
    (
        byte* pointer,
        int?  length
    )
    {
        if (pointer is null)
            return null;

        if (length is { } count)
            return count <= 0 ? string.Empty : Encoding.UTF8.GetString(pointer, count);

        var span = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(pointer);
        return span.IsEmpty ? string.Empty : Encoding.UTF8.GetString(span);
    }

    private static string FormatAddress
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);
}
