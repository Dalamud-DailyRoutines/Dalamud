using System.Collections;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 按成员路径对托管对象做读取、写入与方法调用。
/// </summary>
internal static class ReflectionAccess
{
    private const BindingFlags MEMBER_FLAGS =
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.FlattenHierarchy;

    private const int MAX_ELEMENTS = 512;

    /// <summary>
    /// 沿路径取回值。
    /// </summary>
    /// <param name="root">路径起点。</param>
    /// <param name="segments">路径段。</param>
    /// <returns>取回的值。</returns>
    public static object? Resolve
    (
        object?  root,
        string[] segments
    )
    {
        var current = root;

        foreach (var segment in segments)
        {
            if (current is null)
                throw new McpException($"在读取路径段 \"{segment}\" 之前遇到了空引用。");

            if (TryIndex(current, segment, out var indexed))
            {
                current = indexed;
                continue;
            }

            var member = FindMember(current.GetType(), segment);

            if (member is PropertyInfo { CanRead: true } indexer && indexer.GetIndexParameters().Length > 0)
                continue;

            current = ReadMember(current, member);
        }

        return current;
    }

    /// <summary>
    /// 沿路径写入值，路径的最后一段为目标成员。
    /// </summary>
    /// <param name="root">路径起点。</param>
    /// <param name="segments">路径段。</param>
    /// <param name="rawValue">以文本形式给出的新值。</param>
    /// <returns>写入结果描述。</returns>
    public static string SetValue
    (
        object   root,
        string[] segments,
        string   rawValue
    )
    {
        if (segments.Length == 0)
            throw new McpException("写入操作需要至少一个路径段。");

        var target = root;

        for (var index = 0; index < segments.Length - 1; index++)
        {
            var segment = segments[index];

            if (TryIndex(target, segment, out var indexed))
            {
                target = indexed;
                continue;
            }

            var member = FindMember(target.GetType(), segment);
            target = ReadMember(target, member) ?? throw new McpException($"路径段 \"{segment}\" 的值为空，无法继续写入。");
        }

        var lastSegment = segments[^1];
        var targetType  = target.GetType();

        switch (FindMember(targetType, lastSegment))
        {
            case FieldInfo field:
            {
                var converted = ConvertArgument(rawValue, field.FieldType);
                field.SetValue(target, converted);
                return $"已写入 {targetType.Name}.{field.Name}";
            }

            case PropertyInfo property:
            {
                if (!property.CanWrite)
                    throw new McpException($"{targetType.Name}.{property.Name} 没有 setter。");

                var converted = ConvertArgument(rawValue, property.PropertyType);
                property.SetValue(target, converted);
                return $"已写入 {targetType.Name}.{property.Name}";
            }

            default:
                throw new McpException($"{targetType.Name} 上找不到可写成员 \"{lastSegment}\"。");
        }
    }

    /// <summary>
    /// 调用目标对象上的成员方法。
    /// </summary>
    /// <param name="root">路径起点。</param>
    /// <param name="path">通往目标对象的路径段，可为空表示使用起点本身。</param>
    /// <param name="memberName">方法名。</param>
    /// <param name="arguments">以文本形式给出的实参。</param>
    /// <returns>返回值。</returns>
    public static object? Invoke
    (
        object   root,
        string[] path,
        string   memberName,
        string[] arguments
    )
    {
        var target = path.Length == 0 ? root : Resolve(root, path) ?? throw new McpException("调用目标为空。");

        var candidates = target.GetType()
                               .GetMember(memberName, MemberTypes.Method, MEMBER_FLAGS)
                               .Cast<MethodInfo>()
                               .Where(method => method.GetParameters().Length == arguments.Length)
                               .ToArray();

        if (candidates.Length == 0)
            throw new McpException($"{target.GetType().Name} 上找不到接受 {arguments.Length} 个参数的方法 \"{memberName}\"。");

        McpException? lastError = null;

        foreach (var candidate in candidates)
        {
            try
            {
                var parameters = candidate.GetParameters();
                var converted  = new object?[arguments.Length];
                for (var index = 0; index < arguments.Length; index++)
                    converted[index] = ConvertArgument(arguments[index], parameters[index].ParameterType);

                return candidate.Invoke(target, converted);
            }
            catch (McpException exception)
            {
                lastError = exception;
            }
            catch (TargetInvocationException exception)
            {
                throw new McpException($"调用 {memberName} 时抛出 {exception.InnerException?.GetType().Name}: {exception.InnerException?.Message}");
            }
        }

        throw lastError ?? new McpException($"调用 {memberName} 失败。");
    }

    /// <summary>
    /// 列出对象上的字段与属性以及它们的当前值。
    /// </summary>
    /// <param name="instance">目标对象。</param>
    /// <param name="depth">值的展开层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string DescribeMembers
    (
        object instance,
        int    depth
    )
    {
        if (instance is IEnumerable enumerable and not string)
            return DescribeElements(enumerable, depth);

        var type    = instance.GetType();
        var builder = new StringBuilder(2048);

        builder.Append("{\"type\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
        builder.Append(",\"members\":[");

        var members = type.GetMembers(MEMBER_FLAGS)
                          .Where(member => member is FieldInfo or PropertyInfo)
                          .OrderBy(member => member.Name, StringComparer.Ordinal)
                          .ToArray();

        for (var index = 0; index < members.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var member = members[index];

            string? value = null;
            string? error = null;

            try
            {
                value = ValueFormatter.Format(ReadMember(instance, member), depth);
            }
            catch (Exception exception)
            {
                error = $"{exception.GetType().Name}: {exception.Message}";
            }

            builder.Append("{\"name\":").Append(ValueFormatter.Format(member.Name,                                0));
            builder.Append(",\"kind\":").Append(ValueFormatter.Format(member is FieldInfo ? "field" : "property", 0));
            builder.Append(",\"declaredType\":").Append(ValueFormatter.Format(DeclaredTypeName(member),           0));
            builder.Append(",\"value\":").Append(value ?? "null");
            builder.Append(",\"error\":").Append(ValueFormatter.Format(error, 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string DescribeElements
    (
        IEnumerable enumerable,
        int         depth
    )
    {
        var type    = enumerable.GetType();
        var builder = new StringBuilder(4096);

        builder.Append("{\"type\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
        builder.Append(",\"elements\":[");

        var total     = 0;
        var truncated = false;

        foreach (var element in enumerable)
        {
            if (total >= MAX_ELEMENTS)
            {
                truncated = true;
                break;
            }

            if (total > 0)
                builder.Append(',');

            builder.Append("{\"index\":").Append(total);
            builder.Append(",\"value\":").Append(ValueFormatter.Format(element, depth));
            builder.Append('}');

            total++;
        }

        builder.Append("],\"count\":").Append(total);
        builder.Append(",\"truncated\":").Append(truncated ? "true" : "false");
        builder.Append('}');
        return builder.ToString();
    }

    private static string DeclaredTypeName
    (
        MemberInfo member
    ) => member switch
    {
        FieldInfo field       => field.FieldType.FullName       ?? field.FieldType.Name,
        PropertyInfo property => property.PropertyType.FullName ?? property.PropertyType.Name,
        _                     => member.Name
    };

    private static bool TryIndex
    (
        object      current,
        string      segment,
        out object? value
    )
    {
        value = null;

        var currentType = current.GetType();

        if (currentType.GetCustomAttribute<InlineArrayAttribute>() is not null)
            throw new McpException($"{currentType.Name} 是内联数组，反射取不到它的元素；请改用 mem_read，type 指定宿主结构、path 里用下标或 Length 按原生地址读取。");

        switch (current)
        {
            case Array array when int.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var arrayIndex):
            {
                if (arrayIndex < 0 || arrayIndex >= array.Length)
                    throw new McpException($"数组下标 {arrayIndex} 越界，长度为 {array.Length}。");

                value = array.GetValue(arrayIndex);
                return true;
            }

            case IList list when int.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var listIndex):
            {
                if (listIndex < 0 || listIndex >= list.Count)
                    throw new McpException($"列表下标 {listIndex} 越界，长度为 {list.Count}。");

                value = list[listIndex];
                return true;
            }

            case IDictionary dictionary:
            {
                foreach (DictionaryEntry entry in dictionary)
                {
                    if (string.Equals(Convert.ToString(entry.Key, CultureInfo.InvariantCulture), segment, StringComparison.Ordinal))
                    {
                        value = entry.Value;
                        return true;
                    }
                }

                throw new McpException($"字典中不存在键 \"{segment}\"。");
            }
        }

        return TryIndexer(current, currentType, segment, out value);
    }

    private static bool TryIndexer
    (
        object      current,
        Type        currentType,
        string      segment,
        out object? value
    )
    {
        value = null;

        if (!int.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var index))
            return false;

        var indexer = currentType.GetProperty("Item", MEMBER_FLAGS, null, null, [typeof(int)], null);
        if (indexer is null || !indexer.CanRead)
            return false;

        var count = currentType.GetProperty("Count",  MEMBER_FLAGS)?.GetValue(current)
                 ?? currentType.GetProperty("Length", MEMBER_FLAGS)?.GetValue(current);

        if (count is int length && (index < 0 || index >= length))
            throw new McpException($"下标 {index} 越界，元素个数为 {length}。");

        value = indexer.GetValue(current, [index]);
        return true;
    }

    private static MemberInfo FindMember
    (
        Type   type,
        string name
    )
    {
        var field = type.GetField(name, MEMBER_FLAGS);
        if (field is not null)
            return field;

        var property = type.GetProperties(MEMBER_FLAGS)
                           .FirstOrDefault(candidate => string.Equals(candidate.Name, name, StringComparison.Ordinal));

        if (property is not null)
            return property;

        var available = string.Join
        (
            ", ",
            type.GetMembers(MEMBER_FLAGS)
                .Where(member => member is FieldInfo or PropertyInfo)
                .Select(member => member.Name)
                .Distinct(StringComparer.Ordinal)
                .Take(40)
        );

        throw new McpException($"{type.Name} 上找不到成员 \"{name}\"。可用成员示例: {available}");
    }

    private static object? ReadMember
    (
        object     instance,
        MemberInfo member
    ) => member switch
    {
        FieldInfo field                         => field.GetValue(instance),
        PropertyInfo { CanRead: true } property => property.GetValue(instance),
        PropertyInfo property                   => throw new McpException($"{property.Name} 没有 getter。"),
        _                                       => throw new McpException($"不支持的成员类型 {member.MemberType}。")
    };

    private static object? ConvertArgument
    (
        string raw,
        Type   targetType
    )
    {
        if (targetType == typeof(string))
            return raw;

        var underlying = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (underlying == typeof(nint) || underlying == typeof(IntPtr))
            return (nint)ParseAddress(raw);

        if (underlying == typeof(nuint) || underlying == typeof(UIntPtr))
            return (nuint)ParseAddress(raw);

        if (underlying == typeof(bool))
            return bool.Parse(raw);

        if (underlying.IsEnum)
            return Enum.Parse(underlying, raw, true);

        if (underlying == typeof(char))
            return raw.Length > 0 ? raw[0] : throw new McpException("无法把空字符串转换为 char。");

        if (underlying == typeof(object))
            return raw;

        return underlying.IsPrimitive
                   ? Convert.ChangeType(raw, underlying, CultureInfo.InvariantCulture)
                   : throw new McpException($"暂不支持把文本转换为 {targetType.Name}。");
    }

    private static long ParseAddress
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
