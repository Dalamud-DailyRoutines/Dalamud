using System.Diagnostics;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>object_access</c> 原语：对托管对象的成员路径做读取、写入与方法调用。
/// </summary>
internal static class ObjectAccessTool
{
    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: read、write、invoke、list。list 对集合一次铺开全部元素（上限 512 个），对其它对象列出字段与属性及其当前值。</param>
    /// <param name="root">路径起点。形如 <c>service:IObjectTable</c>、<c>ClientState.LocalPlayer</c>，或 <c>o12</c>（引用 id）。</param>
    /// <param name="path">成员路径，例如 <c>LocalPlayer</c>、<c>Status[0].RemainingTime</c>、<c>Item[1]</c>（Item 段是索引器名，会被跳过，随后的数字段作为下标）或 <c>Count</c>。</param>
    /// <param name="member">invoke 时的目标方法名。</param>
    /// <param name="value">write 时以文本给出的新值。</param>
    /// <param name="arguments">invoke 时以文本给出的实参。</param>
    /// <param name="depth">引用类型向下展开的层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string    action,
        string    root,
        string?   path      = null,
        string?   member    = null,
        string?   value     = null,
        string[]? arguments = null,
        int       depth     = 1
    )
    {
        var (target, segments) = ResolveRoot(root, MemberPath.Parse(path));
        var started = Stopwatch.GetTimestamp();

        string result;

        switch (action.ToLowerInvariant())
        {
            case "read":
            {
                var resolved  = ReflectionAccess.Resolve(target, segments);
                var reference = resolved is null ? null : MCPRuntime.References.TrackObject(resolved);
                result = $"{{\"value\":{ValueFormatter.Format(resolved, depth)},\"ref\":{(reference is null ? "null" : $"\"{reference}\"")}}}";
                break;
            }

            case "write":
            {
                if (value is null)
                    throw new McpException("写入操作需要提供 value。");

                var outcome = ReflectionAccess.SetValue(target, segments, value);
                result = $"{{\"result\":\"{Escape(outcome)}\"}}";
                break;
            }

            case "list":
            {
                var resolved = segments.Length == 0
                                   ? target
                                   : ReflectionAccess.Resolve(target, segments) ?? throw new McpException("路径指向空引用。");

                result = ReflectionAccess.DescribeMembers(resolved, depth);
                break;
            }

            case "invoke":
            {
                if (string.IsNullOrWhiteSpace(member))
                    throw new McpException("调用操作需要提供 member。");

                var returned  = ReflectionAccess.Invoke(target, segments, member, arguments ?? []);
                var reference = returned is null ? null : MCPRuntime.References.TrackObject(returned);
                result = $"{{\"value\":{ValueFormatter.Format(returned, depth)},\"ref\":{(reference is null ? "null" : $"\"{reference}\"")}}}";
                break;
            }

            default:
                throw new McpException($"不支持的操作 \"{action}\"，可用值为 read、write、invoke、list。");
        }

        var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
        MCPRuntime.Trace.Write("object_access", $"{action} {root}.{path ?? string.Empty} member={member}", elapsed);
        return result;
    }

    private static (object Root, string[] Segments) ResolveRoot
    (
        string   root,
        string[] segments
    )
    {
        if (root.StartsWith("service:", StringComparison.OrdinalIgnoreCase))
            return (ServiceResolver.Get(ServiceResolver.FindServiceType(root["service:".Length..].Trim())), segments);

        if (root.Length > 1 && root[0] == 'o' && MCPRuntime.References.TryGetObject(root, out var tracked) && tracked is not null)
            return (tracked, segments);

        var separator = root.IndexOf('.', StringComparison.Ordinal);
        if (separator < 0)
            return (ServiceResolver.Get(ServiceResolver.FindServiceType(root.Trim())), segments);

        var inline = MemberPath.Parse(root[(separator + 1)..]);
        return (ServiceResolver.Get(ServiceResolver.FindServiceType(root[..separator].Trim())), [.. inline, .. segments]);
    }

    private static string Escape
    (
        string value
    ) => value.Replace(@"\", @"\\", StringComparison.Ordinal)
              .Replace("\"", "\\\"", StringComparison.Ordinal);
}
