using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>描述成员并以进程内标识精确选择方法。</summary>
internal static class MemberCatalog
{
    private const           BindingFlags FLAGS = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
    private static readonly ConcurrentDictionary<MemberInfo, string> Identities = new();
    private static readonly ConcurrentDictionary<string, MemberInfo> Members = new(StringComparer.Ordinal);
    private static          int nextId;

    public static string Identify(MemberInfo member)
        => Identities.GetOrAdd
        (
            member,
            item =>
            {
                var id = $"m{Interlocked.Increment(ref nextId)}";
                Members[id] = item;
                return id;
            }
        );


    public static string Describe(Type type, string? filter, int offset, int limit, bool native = false)
    {
        var candidates = type.GetMembers(FLAGS)
                             .Where(member => member is FieldInfo or PropertyInfo or MethodInfo or EventInfo)
                             .Where(member => filter is null || member.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                             .OrderBy(member => member.Name, StringComparer.Ordinal)
                             .ThenBy(member => member.MetadataToken)
                             .ToArray();
        var page = candidates.Skip(Math.Max(offset, 0)).Take(Math.Clamp(limit, 1, 128)).Select(member => DescribeMember(member, native)).ToArray();
        return JsonSerializer.Serialize
        (
            new
            {
                type = type.FullName,
                offset,
                total = candidates.Length,
                nextOffset = offset + page.Length < candidates.Length ?
                                 (int?)(offset + page.Length) :
                                 null,
                members = page
            }
        );
    }

    public static object DescribeMember(MemberInfo member, bool native = false)
        => member switch
        {
            MethodInfo method => new
            {
                id            = Identify(method),
                name          = method.Name,
                kind          = "method",
                declaringType = method.DeclaringType?.FullName,
                isStatic      = method.IsStatic,
                returnType    = method.ReturnType.ToString(),
                supported     = IsSupported(method, native),
                parameters = method.GetParameters().Select
                (parameter => new
                    {
                        name     = parameter.Name,
                        type     = parameter.ParameterType.ToString(),
                        optional = parameter.IsOptional,
                        defaultValue = parameter.HasDefaultValue && parameter.DefaultValue is not DBNull && parameter.DefaultValue != Missing.Value ?
                                           ValueFormatter.Snapshot(parameter.DefaultValue) :
                                           null
                    }
                ).ToArray()
            },
            FieldInfo field => new
            {
                id       = Identify(field),
                name     = field.Name,
                kind     = "field",
                type     = field.FieldType.ToString(),
                isStatic = field.IsStatic,
                writable = !field.IsInitOnly && !field.IsLiteral
            },
            PropertyInfo property => new
            {
                id       = Identify(property),
                name     = property.Name,
                kind     = "property",
                type     = property.PropertyType.ToString(),
                readable = property.CanRead,
                writable = property.CanWrite,
                indexed  = property.GetIndexParameters().Length > 0
            },
            EventInfo eventInfo => new
            {
                id          = Identify(eventInfo),
                name        = eventInfo.Name,
                kind        = "event",
                handlerType = eventInfo.EventHandlerType?.ToString(),
                parameters = eventInfo.EventHandlerType?.GetMethod("Invoke")?.GetParameters().Select
                    (parameter => new { name = parameter.Name, type = parameter.ParameterType.ToString() }).ToArray()
            },
            _ => throw new McpException("不支持的成员类型。")
        };


    public static MethodInfo ResolveMethod(Type type, string member, int? argumentCount = null, bool native = false)
    {
        if (Members.TryGetValue(member, out var registered))
        {
            if (registered is not MethodInfo method || method.DeclaringType is null || !method.DeclaringType.IsAssignableFrom(type))
                throw new McpException($"成员 {member} 不是 {type.FullName} 的方法。");

            if (argumentCount is not null &&
                (argumentCount > method.GetParameters().Length || argumentCount < method.GetParameters().Count(parameter => !parameter.IsOptional)))
                throw new McpException("实参数量与选定成员不匹配。");

            return IsSupported(method, native) ?
                       method :
                       throw new McpException($"方法 {method} 包含当前调用器不支持的签名。");
        }

        var matches = type.GetMethods(FLAGS)
                          .Where(method => method.Name == member)
                          .Where
                          (method => argumentCount is null ||
                                     (method.GetParameters().Count(parameter => !parameter.IsOptional) <= argumentCount &&
                                      method.GetParameters().Length                                    >= argumentCount)
                          )
                          .ToArray();
        if (matches.Length != 1)
            throw new McpException
                ($"方法 {type.FullName}.{member} 无法唯一确定，请先 describe 并使用成员 id。候选：{JsonSerializer.Serialize(matches.Select(method => DescribeMember(method, native)))}");

        return IsSupported(matches[0], native) ?
                   matches[0] :
                   throw new McpException($"方法 {matches[0]} 包含当前调用器不支持的签名。");
    }

    public static bool IsSupported(MethodInfo method, bool native)
    {
        if (method.ContainsGenericParameters || method.IsAbstract || method.ReturnType.IsByRef || method.ReturnType.IsByRefLike)
            return false;

        return method.GetParameters().All
        (parameter =>
             !parameter.ParameterType.IsByRef           &&
             !parameter.ParameterType.IsByRefLike       &&
             !parameter.ParameterType.IsFunctionPointer &&
             (native || !parameter.ParameterType.IsPointer)
        );
    }
}
