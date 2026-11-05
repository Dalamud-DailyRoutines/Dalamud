using System.Collections;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 按成员路径对托管对象做读取、写入与方法调用。
/// </summary>
internal static class ReflectionAccess
{
    private const BindingFlags MEMBER_FLAGS =
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.FlattenHierarchy;

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

            var member = FindMember
            (
                current as Type ?? current.GetType(),
                segment
            );

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
    public static string SetValue(object root, string[] segments, JsonElement rawValue)
    {
        if (segments.Length == 0)
            throw new McpException("写入操作需要至少一个路径段。");

        SetPath(root, segments, 0, rawValue);
        return "已写入目标成员";
    }

    private static void SetPath(object target, string[] segments, int index, JsonElement value)
    {
        var segment = segments[index];

        if (TryIndex(target, segment, out var indexed))
        {
            if (index == segments.Length - 1)
            {
                var elementType = indexed?.GetType() ?? typeof(object);
                WriteIndex(target, segment, RuntimeArguments.Bind(value, elementType));
                return;
            }

            if (indexed is null)
                throw new McpException($"路径段 {segment} 指向 null。");

            SetPath(indexed, segments, index + 1, value);
            if (indexed.GetType().IsValueType)
                WriteIndex(target, segment, indexed);

            return;
        }

        var member = FindMember(target.GetType(), segment);

        if (member is PropertyInfo property && property.GetIndexParameters().Length > 0)
        {
            SetPath(target, segments, index + 1, value);
            return;
        }

        if (index == segments.Length - 1)
        {
            var memberType = member is FieldInfo field ?
                                 field.FieldType :
                                 ((PropertyInfo)member).PropertyType;
            WriteMember(target, member, RuntimeArguments.Bind(value, memberType));
            return;
        }

        var child = ReadMember(target, member) ?? throw new McpException($"路径段 {segment} 指向 null。");
        SetPath(child, segments, index + 1, value);
        if (child.GetType().IsValueType)
            WriteMember(target, member, child);
    }

    private static void WriteMember(object target, MemberInfo member, object? value)
    {
        switch (member)
        {
            case FieldInfo { IsInitOnly: false, IsLiteral: false } field:
                field.SetValue(target, value);
                return;
            case PropertyInfo { CanWrite: true } property:
                property.SetValue(target, value);
                return;
            default:
                throw new McpException($"成员 {member.Name} 不可写入或无法回写值类型。");
        }
    }

    private static void WriteIndex(object target, string segment, object? value)
    {
        switch (target)
        {
            case Array array:
                array.SetValue(value, int.Parse(segment, CultureInfo.InvariantCulture));
                return;
            case IList list:
                list[int.Parse(segment, CultureInfo.InvariantCulture)] = value;
                return;
            case IDictionary dictionary:
                foreach (var key in dictionary.Keys)
                {
                    if (Convert.ToString(key, CultureInfo.InvariantCulture) != segment)
                        continue;

                    dictionary[key] = value;
                    return;
                }

                break;
        }

        var indexer = target.GetType().GetProperty("Item", MEMBER_FLAGS, null, null, [typeof(int)], null);
        if (indexer is not { CanWrite: true })
            throw new McpException("目标没有可写索引器。");

        indexer.SetValue(target, value, [int.Parse(segment, CultureInfo.InvariantCulture)]);
    }

    /// <summary>
    /// 调用目标对象上的成员方法。
    /// </summary>
    /// <param name="root">路径起点。</param>
    /// <param name="path">通往目标对象的路径段，可为空表示使用起点本身。</param>
    /// <param name="memberName">方法名。</param>
    /// <param name="arguments">以文本形式给出的实参。</param>
    /// <returns>返回值。</returns>
    public static object? Invoke(object root, string[] path, string memberName, JsonElement[] arguments)
    {
        var target = path.Length == 0 ?
                         root :
                         Resolve(root, path) ?? throw new McpException("调用目标为空。");
        var method = MemberCatalog.ResolveMethod
        (
            target as Type ?? target.GetType(),
            memberName,
            arguments.Length
        );
        if (target is Type && !method.IsStatic)
            throw new McpException("实例方法需要对象引用。");
        var parameters = method.GetParameters();
        var converted  = new object?[parameters.Length];

        for (var index = 0; index < parameters.Length; index++)
        {
            converted[index] = index < arguments.Length ?
                                   RuntimeArguments.Bind(arguments[index], parameters[index].ParameterType) :
                                   parameters[index].DefaultValue;
        }

        try
        {
            return method.Invoke
            (
                method.IsStatic ?
                    null :
                    target,
                converted
            );
        }
        catch (TargetInvocationException exception)
        {
            throw new McpException($"目标方法抛出 {exception.InnerException?.GetType().Name}: {exception.InnerException?.Message}");
        }
    }

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

        var count = currentType.GetProperty("Count", MEMBER_FLAGS)?.GetValue(current) ?? currentType.GetProperty("Length", MEMBER_FLAGS)?.GetValue(current);

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
}
