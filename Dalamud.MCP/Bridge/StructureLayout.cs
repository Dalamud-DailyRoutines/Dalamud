using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 从类型的布局元数据中读出字段偏移与大小，作为结构化内存读写的依据。
/// </summary>
internal static class StructureLayout
{
    private static readonly Lock                                             CACHE_LOCK  = new();
    private static readonly Dictionary<Type, IReadOnlyList<FieldDescriptor>> FIELD_CACHE = [];
    private static readonly Dictionary<string, Type>                         TYPE_CACHE  = new(StringComparer.Ordinal);

    /// <summary>
    /// 按名称查找类型，优先在 FFXIVClientStructs 中查找。
    /// </summary>
    /// <param name="name">类型全名或简单名。</param>
    /// <returns>类型。</returns>
    public static Type FindType
    (
        string name
    )
    {
        lock (CACHE_LOCK)
        {
            if (TYPE_CACHE.TryGetValue(name, out var cached))
                return cached;
        }

        var matches = new List<Type>();

        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (assembly.IsDynamic)
                continue;

            var exact = assembly.GetType(name, false, false);
            if (exact is not null)
                matches.Add(exact);
        }

        if (matches.Count == 0)
        {
            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assembly.IsDynamic)
                    continue;

                Type[] types;

                try
                {
                    types = assembly.GetTypes();
                }
                catch (ReflectionTypeLoadException exception)
                {
                    types = [.. exception.Types.Where(type => type is not null).Select(type => type!)];
                }

                matches.AddRange(types.Where(type => string.Equals(type.Name, name, StringComparison.Ordinal)));
            }
        }

        var resolved = matches.Count switch
        {
            0 => throw new McpException($"找不到类型 \"{name}\"。"),
            1 => matches[0],
            _ => matches.OrderBy(type => type.Namespace?.StartsWith("FFXIVClientStructs", StringComparison.Ordinal) == true ? 0 : 1)
                        .ThenBy(type => type.FullName, StringComparer.Ordinal)
                        .First()
        };

        lock (CACHE_LOCK)
            TYPE_CACHE[name] = resolved;

        return resolved;
    }

    /// <summary>
    /// 取回类型的字段偏移表。
    /// </summary>
    /// <param name="type">目标类型。</param>
    /// <returns>字段描述序列，按偏移升序排列。</returns>
    public static IReadOnlyList<FieldDescriptor> GetFields
    (
        Type type
    )
    {
        lock (CACHE_LOCK)
        {
            if (FIELD_CACHE.TryGetValue(type, out var cached))
                return cached;
        }

        var fields = new List<FieldDescriptor>();

        foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (field.IsStatic)
                continue;

            var offset = ResolveOffset(type, field);
            if (offset < 0)
                continue;

            fields.Add(new FieldDescriptor(field.Name, field.FieldType, offset, GetFieldSize(field.FieldType)));
        }

        fields.Sort((left, right) => left.Offset.CompareTo(right.Offset));

        lock (CACHE_LOCK)
        {
            FIELD_CACHE[type] = fields;
            return fields;
        }
    }

    /// <summary>
    /// 按名称取回单个字段描述。
    /// </summary>
    /// <param name="type">目标类型。</param>
    /// <param name="name">字段名。</param>
    /// <returns>字段描述。</returns>
    public static FieldDescriptor FindField
    (
        Type   type,
        string name
    )
    {
        var fields = GetFields(type);

        foreach (var field in fields)
        {
            if (string.Equals(field.Name, name, StringComparison.Ordinal))
                return field;
        }

        foreach (var field in fields)
        {
            if (string.Equals(field.Name.TrimStart('_'), name, StringComparison.OrdinalIgnoreCase))
                return field;
        }

        var available = string.Join(", ", fields.Take(40).Select(field => field.Name));
        throw new McpException($"{type.Name} 上找不到字段 \"{name}\"。可用字段: {available}");
    }

    /// <summary>
    /// 判断类型是否为内联数组，并取回元素类型与元素个数。
    /// </summary>
    /// <param name="type">目标类型。</param>
    /// <returns>元素类型与个数，不是内联数组时为 null。</returns>
    public static (Type ElementType, int Count)? TryGetInlineArray
    (
        Type type
    )
    {
        if (type.GetCustomAttribute<InlineArrayAttribute>() is not { } attribute)
            return null;

        var elementType = type.IsGenericType ? type.GetGenericArguments()[0] : typeof(byte);
        return (elementType, attribute.Length);
    }

    /// <summary>
    /// 取回类型的字节大小，无法确定时返回 -1。
    /// </summary>
    /// <param name="type">目标类型。</param>
    /// <returns>字节大小，未知时为 -1。</returns>
    public static int GetSize
    (
        Type type
    )
    {
        var layout = type.StructLayoutAttribute;
        if (layout is { Size: > 0 })
            return layout.Size;

        if (type.IsPointer)
            return IntPtr.Size;

        if (type.IsEnum)
            return GetSize(Enum.GetUnderlyingType(type));

        try
        {
            return Marshal.SizeOf(type);
        }
        catch (ArgumentException)
        {
            return -1;
        }
    }

    /// <summary>
    /// 判断类型是否是可以直接读写的标量。
    /// </summary>
    /// <param name="type">目标类型。</param>
    /// <returns>是否为标量。</returns>
    public static bool IsScalar
    (
        Type type
    ) =>
        type.IsPrimitive || type.IsEnum || type.IsPointer || type == typeof(nint) || type == typeof(nuint) || type == typeof(IntPtr) || type == typeof(UIntPtr);

    private static int ResolveOffset
    (
        Type      type,
        FieldInfo field
    )
    {
        var attribute = field.GetCustomAttribute<FieldOffsetAttribute>();
        if (attribute is not null)
            return attribute.Value;

        try
        {
            return Marshal.OffsetOf(type, field.Name).ToInt32();
        }
        catch (ArgumentException)
        {
            return -1;
        }
    }

    private static int GetFieldSize
    (
        Type fieldType
    )
    {
        if (fieldType.IsPointer)
            return IntPtr.Size;

        if (fieldType.IsEnum)
            return GetSize(Enum.GetUnderlyingType(fieldType));

        return fieldType.IsPrimitive
                   ? Marshal.SizeOf(fieldType)
                   : GetSize(fieldType);
    }
}
