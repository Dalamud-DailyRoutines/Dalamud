using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>observe</c> 原语：安装观察点，覆盖内存变化、原生挂钩、托管挂钩与托管事件。
/// </summary>
internal static class ObserveTool
{
    private const BindingFlags METHOD_FLAGS =
        BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: add、list、remove。</param>
    /// <param name="mode">观察模式: memwatch、hook、managedhook、hostevent。</param>
    /// <param name="address">memwatch 的目标地址。</param>
    /// <param name="type">hook 与 managedhook 的类型名。</param>
    /// <param name="member">hook 与 managedhook 的方法名；hostevent 的事件名。</param>
    /// <param name="instance">hostevent 的事件源，取引用 id 或 service:类型名。</param>
    /// <param name="valueType">memwatch 的值类型名。</param>
    /// <param name="length">hwbp 数据长度。</param>
    /// <param name="pollIntervalMs">memwatch 轮询间隔。</param>
    /// <param name="captureBytes">memwatch 每次抓取字节数。</param>
    /// <param name="id">remove 时的观察点 id。</param>
    /// <param name="limit">list 的最大条数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? mode           = null,
        string? address        = null,
        string? type           = null,
        string? member         = null,
        string? instance       = null,
        string? valueType      = null,
        int     pollIntervalMs = 50,
        int     captureBytes   = 16,
        string? id             = null,
        int     limit          = 32
    )
    {
        return action.ToLowerInvariant() switch
        {
            "add"    => Add(mode, address, type, member, instance, valueType, pollIntervalMs, captureBytes),
            "list"   => List(Math.Clamp(limit, 1, 500)),
            "remove" => Remove(id),
            _        => throw new McpException($"不支持的操作 \"{action}\"，可用值为 add、list、remove。")
        };
    }

    private static string Add
    (
        string? mode,
        string? address,
        string? type,
        string? member,
        string? instance,
        string? valueType,
        int     pollIntervalMs,
        int     captureBytes
    )
    {
        var normalized = (mode ?? string.Empty).ToLowerInvariant();
        var store      = MCPRuntime.Observations;
        var id         = store.NextObservationId();

        switch (normalized)
        {
            case "memwatch":
            {
                var target = Require(address, "memwatch 需要提供 address。");
                var observation = new Observation(id, "memwatch", target, Math.Max(pollIntervalMs, 1), Math.Clamp(captureBytes, 1, 4096))
                {
                    Address   = (nint)MemoryAccess.ParseAddress(target),
                    ValueType = valueType
                };

                MCPRuntime.EnsureWatcher();
                store.Add(observation);
                return Describe(observation);
            }

            case "hook":
            {
                var symbol      = ResolveFfcsSymbol(type, member);
                var observation = new Observation(id, "hook", $"{symbol.TypeName}.{symbol.MemberName}", 0, 0);
                store.Add(observation);

                var hook = HookBridge.Install(store, observation, symbol.Address, symbol.ParameterTypes, symbol.ReturnType);
                MCPRuntime.Hooks[id] = hook;

                var builder = new StringBuilder(256);
                builder.Append("{\"id\":").Append(ValueFormatter.Format(id, 0));
                builder.Append(",\"mode\":\"hook\"");
                builder.Append(",\"symbol\":").Append(ValueFormatter.Format($"{symbol.TypeName}.{symbol.MemberName}",     0));
                builder.Append(",\"address\":").Append(ValueFormatter.Format(MemoryScanner.FormatAddress(symbol.Address), 0));
                builder.Append(",\"parameters\":").Append(symbol.ParameterTypes.Length);
                builder.Append('}');
                return builder.ToString();
            }

            case "managedhook":
            {
                var targetType   = StructureLayout.FindType(Require(type,        "managedhook 需要提供 type。"));
                var targetMethod = FindManagedMethod(targetType, Require(member, "managedhook 需要提供 member。"));
                var observation  = new Observation(id, "managedhook", $"{targetType.Name}.{targetMethod.Name}", 0, 0);
                store.Add(observation);
                ManagedHookManager.Patch(observation, targetMethod);
                return Describe(observation);
            }

            case "hostevent":
            {
                var source    = ResolveEventSource(instance);
                var eventName = Require(member, "hostevent 需要提供 member 作为事件名。");
                var eventInfo = source.GetType().GetEvent(eventName, METHOD_FLAGS) ?? throw new McpException($"类型 {source.GetType().Name} 上找不到事件 \"{eventName}\"。");

                var observation = new Observation(id, "hostevent", $"{source.GetType().Name}.{eventName}", 0, 0)
                {
                    Source    = source,
                    EventName = eventName
                };

                var handler = EventBinder.Bind(store, observation, eventInfo);
                eventInfo.AddEventHandler(source, handler);
                observation.Handler = handler;
                store.Add(observation);

                return Describe(observation);
            }

            default:
                throw new McpException($"不支持的观察模式 \"{mode}\"，可用值为 memwatch、hook、managedhook、hostevent。");
        }
    }

    private static string List
    (
        int limit
    )
    {
        var builder = new StringBuilder(1024);
        builder.Append("{\"observations\":[");

        var entries = MCPRuntime.Observations.List().Take(limit).ToArray();

        for (var index = 0; index < entries.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append(RenderObservation(entries[index]));
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string Remove
    (
        string? id
    )
    {
        var target      = Require(id, "remove 需要提供 id。");
        var observation = MCPRuntime.Observations.Remove(target) ?? throw new McpException($"观察点 \"{target}\" 不存在。");

        switch (observation.Mode)
        {
            case "memwatch":
                break;

            case "hook":
                if (MCPRuntime.Hooks.TryRemove(target, out var hook))
                    HookBridge.Uninstall(target, hook);
                break;

            case "managedhook":
                ManagedHookManager.Unpatch(target);
                break;

            case "hostevent":
                if (observation.Handler is { } handler && observation.Source is { } source && observation.EventName is { } eventName)
                {
                    var eventInfo = source.GetType().GetEvent(eventName, METHOD_FLAGS);
                    eventInfo?.RemoveEventHandler(source, handler);
                }

                break;
        }

        return "{\"removed\":" + ValueFormatter.Format(target, 0) + ",\"mode\":" + ValueFormatter.Format(observation.Mode, 0) + "}";
    }

    private static object ResolveEventSource
    (
        string? instance
    )
    {
        var target = Require(instance, "hostevent 需要提供 instance（引用 id、service:类型名 或 服务类型名）。");

        if (target.StartsWith("service:", StringComparison.OrdinalIgnoreCase))
            return ServiceResolver.Get(ServiceResolver.FindServiceType(target["service:".Length..].Trim()));

        if (MCPRuntime.References.TryGetObject(target, out var tracked) && tracked is not null)
            return tracked;

        var separator = target.IndexOf('.', StringComparison.Ordinal);
        if (separator > 0 && MCPRuntime.References.TryGetObject(target[..separator], out var outer) && outer is not null)
        {
            return ReflectionAccess.Resolve(outer, MemberPath.Parse(target[(separator + 1)..]))
                   ?? throw new McpException($"事件源 \"{target}\" 解析为空引用。");
        }

        return ServiceResolver.Get(ServiceResolver.FindServiceType(target));
    }

    private static MethodInfo FindManagedMethod
    (
        Type   type,
        string member
    ) =>
        type.GetMember(member, MemberTypes.Method, METHOD_FLAGS)
            .Cast<MethodInfo>()
            .FirstOrDefault(method => !method.IsAbstract) ??
        throw new McpException($"{type.Name} 上找不到可挂钩的方法 \"{member}\"。");

    private static FfcsSymbol ResolveFfcsSymbol
    (
        string? typeName,
        string? member
    )
    {
        var resolvedType = StructureLayout.FindType(Require(typeName, "hook 需要提供 type。"));
        var memberName   = Require(member, "hook 需要提供 member。");

        var method = resolvedType.GetMember(memberName, MemberTypes.Method, METHOD_FLAGS)
                                 .Cast<MethodInfo>()
                                 .FirstOrDefault() ??
                     throw new McpException($"{resolvedType.Name} 上找不到方法 \"{memberName}\"。");

        var address = ReadSymbolAddress(resolvedType, memberName);

        var parameters = method.GetParameters().Select(parameter => parameter.ParameterType).ToList();
        if (!method.IsStatic)
            parameters.Insert(0, typeof(nint));

        return new FfcsSymbol(resolvedType.Name, memberName, address, [.. parameters], method.ReturnType);
    }

    private static nint ReadSymbolAddress
    (
        Type   type,
        string memberName
    )
    {
        var addressClass = type.GetNestedType("Addresses", BindingFlags.Public | BindingFlags.NonPublic) ?? throw new McpException($"{type.Name} 没有登记签名，无法定位地址。");

        var field = addressClass.GetField
                        (memberName, BindingFlags.Public | BindingFlags.Static | BindingFlags.NonPublic) ??
                    throw new McpException($"{type.Name} 没有名为 {memberName} 的签名登记。");

        var value   = field.GetValue(null);
        var address = (nint)(value?.GetType().GetField("Value")?.GetValue(value) ?? 0);

        return address == 0
                   ? throw new McpException($"{type.Name}.{memberName} 的签名尚未解析出地址。")
                   : address;
    }

    private static string Require
    (
        string? value,
        string  message
    ) =>
        string.IsNullOrWhiteSpace(value) ? throw new McpException(message) : value;

    private static string Describe
    (
        Observation observation
    )
    {
        var builder = new StringBuilder(256);
        builder.Append("{\"id\":").Append(ValueFormatter.Format(observation.Id,         0));
        builder.Append(",\"mode\":").Append(ValueFormatter.Format(observation.Mode,     0));
        builder.Append(",\"target\":").Append(ValueFormatter.Format(observation.Target, 0));
        builder.Append('}');
        return builder.ToString();
    }

    private static string RenderObservation
    (
        Observation observation
    )
    {
        var builder = new StringBuilder(256);
        builder.Append("{\"id\":").Append(ValueFormatter.Format(observation.Id,         0));
        builder.Append(",\"mode\":").Append(ValueFormatter.Format(observation.Mode,     0));
        builder.Append(",\"target\":").Append(ValueFormatter.Format(observation.Target, 0));
        builder.Append(",\"evidence\":").Append(observation.EvidenceCount);
        builder.Append(",\"dropped\":").Append(observation.DroppedCount);
        builder.Append(",\"createdAt\":").Append
        (
            ValueFormatter.Format
            (
                observation.CreatedAt.ToString("O", CultureInfo.InvariantCulture),
                0
            )
        );
        builder.Append('}');
        return builder.ToString();
    }

    private sealed class FfcsSymbol
    {
        public FfcsSymbol
        (
            string typeName,
            string memberName,
            nint   address,
            Type[] parameterTypes,
            Type   returnType
        )
        {
            this.TypeName       = typeName;
            this.MemberName     = memberName;
            this.Address        = address;
            this.ParameterTypes = parameterTypes;
            this.ReturnType     = returnType;
        }

        public string TypeName { get; }

        public string MemberName { get; }

        public nint Address { get; }

        public Type[] ParameterTypes { get; }

        public Type ReturnType { get; }
    }
}
