using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>ffcs_call</c> 原语：复用 FFXIVClientStructs 生成的方法，对原生实例调用成员函数。
/// </summary>
internal static class FfcsCallTool
{
    private const BindingFlags METHOD_FLAGS =
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

    /// <summary>
    /// 执行调用。
    /// </summary>
    /// <param name="type">结构体类型全名或简单名。</param>
    /// <param name="member">方法名。</param>
    /// <param name="instance">实例地址，实例方法必填。</param>
    /// <param name="arguments">以文本给出的实参。</param>
    /// <param name="depth">返回值中引用类型的展开层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string    type,
        string    member,
        string?   instance  = null,
        string[]? arguments = null,
        int       depth     = 1
    )
    {
        var structType   = StructureLayout.FindType(type);
        var rawArguments = arguments ?? [];
        var method       = FindMethod(structType, member, rawArguments.Length);

        var thisPointer = instance is null ? 0 : (nint)MemoryAccess.ParseAddress(instance);
        if (!method.IsStatic && thisPointer == 0)
            throw new McpException($"{structType.Name}.{member} 是实例方法，需要提供 instance 地址。");

        if (!method.IsStatic && !MemoryAccess.IsRangeReadable(thisPointer, 8))
            throw new McpException($"实例地址 0x{(long)thisPointer:x} 不可读，已拒绝调用 {structType.Name}.{member}。");

        var started = Stopwatch.GetTimestamp();
        var result  = InteropInvoker.Invoke(method, thisPointer, rawArguments);
        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

        MCPRuntime.Trace.Write("ffcs_call", $"{structType.Name}.{member} this={instance} args=[{string.Join(",", rawArguments)}]", elapsed);

        var formatted = result switch
        {
            null           => "null",
            IntPtr pointer => "\"" + "0x" + pointer.ToInt64().ToString("x", CultureInfo.InvariantCulture) + "\"",
            _              => ValueFormatter.Format(result, depth)
        };

        return "{\"type\":"                                                     +
               ValueFormatter.Format(structType.FullName ?? structType.Name, 0) +
               ",\"member\":"                                                   +
               ValueFormatter.Format(member, 0)                                 +
               ",\"static\":"                                                   +
               (method.IsStatic ? "true" : "false")                             +
               ",\"return\":"                                                   +
               formatted                                                        +
               "}";
    }

    private static MethodInfo FindMethod
    (
        Type   structType,
        string member,
        int    argumentCount
    )
    {
        var candidates = structType
                         .GetMember(member, MemberTypes.Method, METHOD_FLAGS)
                         .Cast<MethodInfo>()
                         .ToArray();

        if (candidates.Length == 0)
            throw new McpException($"{structType.Name} 上找不到方法 \"{member}\"。");

        var matched = candidates.Where(method => method.GetParameters().Length == argumentCount).ToArray();

        if (matched.Length == 0)
        {
            var signatures = string.Join
            (
                ", ",
                candidates.Select(method => $"{method.Name}({string.Join(",", method.GetParameters().Select(p => p.ParameterType.Name))})")
            );
            throw new McpException($"{structType.Name}.{member} 没有接受 {argumentCount} 个参数的重载。可用: {signatures}");
        }

        return matched
               .OrderByDescending(method => method.GetParameters().Count(parameter => !parameter.ParameterType.IsPointer))
               .First();
    }
}
