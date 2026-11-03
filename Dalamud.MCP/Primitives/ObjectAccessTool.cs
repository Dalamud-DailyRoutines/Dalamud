using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Game;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>发现、查询和操作托管对象。</summary>
internal static class ObjectAccessTool
{
    public enum Operation
    {
        Types,
        Describe,
        Read,
        Query,
        Write,
        Invoke,
        Task,
        Release
    }

    public enum ExecutionThread
    {
        Framework, Worker
    }

    public static async Task<string> Run
    (
        [Description("types 搜索类型；describe 只返回元数据；read 读取路径；query 分页筛选集合；write 写入；invoke 调用；task 等待任务；release 释放引用。")]
        Operation action,
        [Description("service:服务名、o编号，或 type:类型全名（元数据与静态方法）。")]
        string? root = null,
        [Description("对象成员路径，支持点号、数字下标与字典键。")] string? path = null,
        [Description("describe 返回的方法 id；名称仅在无歧义时可用。")]
        string? member = null,
        [Description("JSON 新值，以 JSON 文本传入；对象引用写作 {\"ref\":\"o编号\"}，JSON null 写作 null。")]
        string? value = null,
        JsonElement[]? arguments = null,
        [Description("read 的多个路径，在一次线程调度中顺序读取。")]
        string[]? paths = null,
        [Description("query 仅返回这些字段路径。")] string[]? fields = null,
        [Description("query 的精确匹配条件，键为字段路径，值为 JSON 标量。")]
        Dictionary<string, JsonElement>? where = null,
        [Description("types 或 describe 的名称包含过滤。")]
        string? filter = null,
        int offset = 0,
        int limit  = 32,
        int depth  = 0,
        [Description("默认 framework；确认目标允许后台访问时才选 worker。")]
        ExecutionThread thread = ExecutionThread.Framework,
        double            timeoutSeconds    = 5,
        CancellationToken cancellationToken = default
    )
    {
        if (action == Operation.Types)
        {
            if (string.IsNullOrWhiteSpace(filter))
                throw new McpException("types 需要 filter，避免无界枚举。");

            var types = AppDomain.CurrentDomain.GetAssemblies().Where(assembly => !assembly.IsDynamic).SelectMany
            (assembly =>
                {
                    try
                    {
                        return assembly.GetTypes();
                    }
                    catch (ReflectionTypeLoadException exception)
                    {
                        return [.. exception.Types.Where(type => type is not null).Select(type => type!)];
                    }
                }
            ).Where(type => (type.FullName ?? type.Name).Contains(filter, StringComparison.OrdinalIgnoreCase)).OrderBy
                (type => type.FullName, StringComparer.Ordinal).ToArray();
            return JsonSerializer.Serialize
                (new { total = types.Length, types = types.Skip(Math.Max(offset, 0)).Take(Math.Clamp(limit, 1, 128)).Select(type => type.FullName).ToArray() });
        }

        if (root is null)
            throw new McpException("需要 root。");

        if (action == Operation.Release)
            return JsonSerializer.Serialize(new { released = MCPRuntime.References.Release(root) });

        var target = ResolveRoot(root);

        if (action == Operation.Task)
        {
            if (target is not Task task)
                throw new McpException("root 不是任务引用。");

            try
            {
                await task.WaitAsync(TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 0.1, 15)), cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return JsonSerializer.Serialize(new { status = task.Status.ToString(), completed = false, reference = root });
            }
            catch (Exception) when (task.IsCompleted)
            {
                return JsonSerializer.Serialize
                    (new { status = task.Status.ToString(), completed = true, error = task.Exception?.GetBaseException().Message, cancelled = task.IsCanceled });
            }

            var result = task.GetType().GetProperty("Result")?.GetValue(task);
            return JsonSerializer.Serialize(new { completed = true, status = task.Status.ToString(), value = ValueFormatter.Snapshot(result, depth) });
        }

        if (thread == ExecutionThread.Worker)
            return Execute();

        return await Service<Framework>.Get().Run(Execute, cancellationToken).ConfigureAwait(false);

        string Execute()
        {
            cancellationToken.ThrowIfCancellationRequested();
            var segments = MemberPath.Parse(path);

            if (action == Operation.Read)
            {
                if (paths is { Length: > 0 })
                {
                    if (paths.Length > 128)
                        throw new McpException("一次最多读取 128 个路径。");

                    var values = paths.Select
                    (item => new
                        {
                            path = item, value = ValueFormatter.Snapshot(ReflectionAccess.Resolve(target, [.. segments, .. MemberPath.Parse(item)]), depth)
                        }
                    ).ToArray();
                    return JsonSerializer.Serialize(new { consistency = "sequential_in_one_dispatch", thread = thread.ToString(), values });
                }

                return JsonSerializer.Serialize(new { value = ValueFormatter.Snapshot(ReflectionAccess.Resolve(target, segments), depth) });
            }

            var resolved = segments.Length == 0 ?
                               target :
                               ReflectionAccess.Resolve(target, segments) ?? throw new McpException("目标路径指向 null。");

            switch (action)
            {
                case Operation.Describe:
                    return MemberCatalog.Describe
                    (
                        resolved as Type ?? resolved.GetType(),
                        filter,
                        offset,
                        limit
                    );
                case Operation.Query:
                    return Query(resolved, fields, where, offset, limit, depth, cancellationToken);
                case Operation.Write:
                {
                    if (value is null)
                        throw new McpException("write 需要 value，JSON null 请以文本 null 传入。");

                    using var document = JsonDocument.Parse(value);
                    return JsonSerializer.Serialize(new { result = ReflectionAccess.SetValue(target, segments, document.RootElement) });
                }
                case Operation.Invoke:
                    if (string.IsNullOrWhiteSpace(member))
                        throw new McpException("invoke 需要 member。");

                    return JsonSerializer.Serialize
                        (new { value = ValueFormatter.Snapshot(ReflectionAccess.Invoke(target, segments, member, arguments ?? []), depth) });
                default:
                    throw new McpException("未知对象操作。");
            }
        }

    }

    private static object ResolveRoot(string root)
    {
        if (ReferenceTable.IsObjectReference(root))
            return MCPRuntime.References.GetObject(root);

        if (root.StartsWith("type:", StringComparison.Ordinal))
            return StructureLayout.FindType(root[5..]);

        var name = root.StartsWith("service:", StringComparison.Ordinal) ?
                       root[8..] :
                       root;
        return ServiceResolver.Get(ServiceResolver.FindServiceType(name));
    }

    private static string Query
        (object target, string[]? fields, Dictionary<string, JsonElement>? where, int offset, int limit, int depth, CancellationToken cancellationToken)
    {
        if (target is not IEnumerable enumerable || target is string)
            throw new McpException("query 需要集合目标。");

        if (offset < 0 || offset > 4096 || fields?.Length > 32 || where?.Count > 16)
            throw new McpException("offset 范围为 0 至 4096，字段最多 32 个，条件最多 16 个。");

        var items   = new JsonArray();
        var scanned = 0;
        var matched = 0;
        var more    = false;

        foreach (var item in enumerable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (scanned++ >= 8192)
                throw new McpException("集合扫描超过 8192 项，请缩小目标集合。");

            if (where is not null &&
                where.Any
                (condition => !JsonNode.DeepEquals
                              (
                                  ValueFormatter.Snapshot(ReflectionAccess.Resolve(item, MemberPath.Parse(condition.Key))),
                                  JsonNode.Parse(condition.Value.GetRawText())
                              )
                ))
                continue;

            if (matched++ < offset)
                continue;

            if (items.Count >= Math.Clamp(limit, 1, 128))
            {
                more = true;
                break;
            }

            if (fields is not { Length: > 0 })
            {
                items.Add(ValueFormatter.Snapshot(item, depth));
                continue;
            }

            var projected = new JsonObject();
            if (item is not null && !item.GetType().IsValueType)
                projected["ref"] = MCPRuntime.References.TrackObject(item);

            foreach (var field in fields)
                projected[field] = ValueFormatter.Snapshot(ReflectionAccess.Resolve(item, MemberPath.Parse(field)), depth);

            items.Add(projected);
        }

        return JsonSerializer.Serialize
        (
            new
            {
                offset, nextOffset = more ?
                                         (int?)(offset + items.Count) :
                                         null,
                consistency = "live_collection", scanned, items
            }
        );
    }
}
