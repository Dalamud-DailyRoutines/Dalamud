using System.Linq;
using System.Reflection;
using System.ComponentModel;
using System.Text.Json;
using InteropGenerator.Runtime;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>安装有采样、期限和记录上限的观察点。</summary>
internal static class ObserveTool
{
    public enum Operation
    {
        Add, List, Remove
    }

    public enum ObservationMode
    {
        Memwatch,
        Hook,
        Managedhook,
        Hostevent
    }

    public static string Run
    (
        Operation        action,
        ObservationMode? mode    = null,
        string?          address = null,
        string?          type    = null,
        [Description("方法使用 describe 返回的成员 id；事件使用事件名。")]
        string? member = null,
        [Description("事件源引用 o编号 或 service:服务名。")]
        string? instance = null,
        string? valueType      = null,
        int     pollIntervalMs = 50,
        int     captureBytes   = 16,
        string? id             = null,
        int     limit          = 32,
        [Description("每 N 次命中采集一次，范围 1 至 100000。")]
        int sampleEvery = 1,
        [Description("最多记录数量，范围 1 至 4096；到达后自动解除观察。")]
        int maxRecords = 256,
        [Description("观察有效期秒数，范围 1 至 3600。")] double durationSeconds = 300
    )
    {
        switch (action)
        {
            case Operation.Add:
                return Add
                (
                    mode ?? throw new McpException("add 需要 mode。"),
                    address,
                    type,
                    member,
                    instance,
                    valueType,
                    pollIntervalMs,
                    captureBytes,
                    sampleEvery,
                    maxRecords,
                    durationSeconds
                );
            case Operation.List:
                var all = MCPRuntime.Observations.List();
                return JsonSerializer.Serialize(new { total = all.Count, observations = all.Take(Math.Clamp(limit, 1, 256)).Select(Describe).ToArray() });
            case Operation.Remove:
                return JsonSerializer.Serialize(new { removed = Remove(id ?? throw new McpException("remove 需要 id。")) });
            default:
                throw new McpException("未知观察操作。");
        }
    }

    internal static bool Remove(string id)
    {
        var observation = MCPRuntime.Observations.Get(id);
        if (observation is null)
            return false;

        observation.Active = false;
        if (MCPRuntime.Hooks.TryRemove(id, out var hook))
            HookBridge.Uninstall(id, hook);

        ManagedHookManager.Unpatch(id);
        if (observation.Handler is { } handler && observation.Source is { } source && observation.EventName is { } eventName)
            source.GetType().GetEvent(eventName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)?.RemoveEventHandler(source, handler);

        MCPRuntime.Observations.Remove(id);
        return true;
    }

    private static string Add
    (
        ObservationMode mode,
        string?         address,
        string?         type,
        string?         member,
        string?         instance,
        string?         valueType,
        int             pollIntervalMs,
        int             captureBytes,
        int             sampleEvery,
        int             maxRecords,
        double          durationSeconds
    )
    {
        var store = MCPRuntime.Observations;
        if (store.List().Count >= 64)
            throw new McpException("最多同时安装 64 个观察点。");

        var id = store.NextObservationId();
        var observation = new Observation
        (
            id,
            mode.ToString().ToLowerInvariant(),
            type ?? address ?? instance ?? string.Empty,
            Math.Clamp(pollIntervalMs, 10, 60000),
            Math.Clamp(captureBytes,   1,  4096)
        )
        {
            SampleEvery = Math.Clamp(sampleEvery, 1, 100000),
            MaxRecords  = Math.Clamp(maxRecords,  1, 4096),
            ExpiresAt   = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(durationSeconds, 1, 3600)),
            ValueType   = valueType
        };
        store.Add(observation);

        try
        {
            switch (mode)
            {
                case ObservationMode.Memwatch:
                    observation.Address   = (nint)MemoryAccess.ParseAddress(address ?? throw new McpException("memwatch 需要 address。"));
                    observation.LastBytes = MemoryAccess.ReadBytes(observation.Address, observation.CaptureBytes);
                    break;
                case ObservationMode.Hook:
                    var nativeType   = StructureLayout.FindType(type                  ?? throw new McpException("hook 需要 type。"));
                    var nativeMethod = MemberCatalog.ResolveMethod(nativeType, member ?? throw new McpException("hook 需要 member。"), native: true);
                    var parameters   = nativeMethod.GetParameters().Select(parameter => parameter.ParameterType).ToList();
                    if (!nativeMethod.IsStatic)
                        parameters.Insert(0, typeof(nint));

                    if (parameters.Any(parameter => !CanHook(parameter)) || !CanHook(nativeMethod.ReturnType))
                        throw new McpException("原生挂钩仅支持基础类型、枚举、指针及 void 返回值。");

                    var addressType = nativeType.GetNestedType("Addresses", BindingFlags.Public    | BindingFlags.NonPublic);
                    var symbol      = addressType?.GetField(nativeMethod.Name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)?.GetValue(null);
                    if (symbol is not Address { Value: not 0 } resolvedSymbol)
                        throw new McpException("该方法没有已解析的原生地址。");

                    MCPRuntime.Hooks[id] = HookBridge.Install(store, observation, resolvedSymbol.Value, [.. parameters], nativeMethod.ReturnType);
                    break;
                case ObservationMode.Managedhook:
                    var managedType = StructureLayout.FindType(type                                       ?? throw new McpException("managedhook 需要 type。"));
                    ManagedHookManager.Patch(observation, MemberCatalog.ResolveMethod(managedType, member ?? throw new McpException("managedhook 需要 member。")));
                    break;
                case ObservationMode.Hostevent:
                    var sourceName = instance ?? throw new McpException("hostevent 需要 instance。");
                    var source = ReferenceTable.IsObjectReference(sourceName) ?
                                     MCPRuntime.References.GetObject(sourceName) :
                                     ServiceResolver.Get
                                     (
                                         ServiceResolver.FindServiceType
                                         (
                                             sourceName.StartsWith("service:", StringComparison.Ordinal) ?
                                                 sourceName[8..] :
                                                 sourceName
                                         )
                                     );
                    var eventName = member ?? throw new McpException("hostevent 需要事件名。");
                    var eventInfo = source.GetType().GetEvent(eventName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance) ??
                                    throw new McpException($"找不到事件 {eventName}。");
                    observation.Source    = source;
                    observation.EventName = eventName;
                    observation.Handler   = EventBinder.Bind(store, observation, eventInfo);
                    eventInfo.AddEventHandler(source, observation.Handler);
                    break;
                default:
                    throw new McpException("未知观察模式。");
            }

            MCPRuntime.EnsureWatcher();
            return JsonSerializer.Serialize(Describe(observation));
        }
        catch
        {
            Remove(id);
            throw;
        }
    }

    private static bool CanHook(Type type) => type == typeof(void) || type.IsPrimitive || type.IsEnum || type.IsPointer;

    private static object Describe(Observation observation) => new
    {
        id          = observation.Id,
        mode        = observation.Mode,
        target      = observation.Target,
        active      = observation.Active,
        expiresAt   = observation.ExpiresAt,
        sampleEvery = observation.SampleEvery,
        maxRecords  = observation.MaxRecords,
        evidence    = observation.EvidenceCount,
        hits        = observation.Hits,
        skipped     = observation.Skipped,
        dropped     = observation.DroppedCount
    };
}
