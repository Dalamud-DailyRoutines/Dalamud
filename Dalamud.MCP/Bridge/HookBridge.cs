using System.Collections.Concurrent;
using System.Linq.Expressions;
using System.Reflection;
using System.Reflection.Emit;
using Dalamud.Hooking;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 运行时合成目标签名的委托，装入 <see cref="Hook{T}"/> 后在命中时记录证据并转调原始函数。
/// </summary>
internal static class HookBridge
{
    private static readonly ConcurrentDictionary<string, Delegate>         ORIGINALS = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, ObservationStore> STORES    = new(StringComparer.Ordinal);

    /// <summary>
    /// 按签名安装一个原生挂钩。
    /// </summary>
    /// <param name="store">观察点仓库。</param>
    /// <param name="observation">观察点。</param>
    /// <param name="address">目标地址。</param>
    /// <param name="parameterTypes">参数类型，实例方法需包含 this 指针。</param>
    /// <param name="returnType">返回类型。</param>
    /// <returns>挂钩对象。</returns>
    public static object Install
    (
        ObservationStore store,
        Observation      observation,
        nint             address,
        Type[]           parameterTypes,
        Type             returnType
    )
    {
        if (address == 0)
            throw new McpException("挂钩需要一个非零地址。");

        if (!MemoryAccess.IsRangeReadable(address, 1))
            throw new McpException($"地址 0x{(long)address:x} 不可读，拒绝挂钩。");

        var delegateType = Expression.GetDelegateType([.. parameterTypes, returnType]);
        var detour       = BuildDetour(observation.Id, delegateType, returnType, parameterTypes);

        var fromAddress = typeof(Hook<>)
                          .MakeGenericType(delegateType)
                          .GetMethod("FromAddress", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public) ??
                          throw new McpException("找不到 Hook<T>.FromAddress。");

        var hook = fromAddress.Invoke(null, [address, detour, Assembly.GetExecutingAssembly()]) ?? throw new McpException("创建挂钩失败。");

        var original = hook.GetType().GetProperty("Original")?.GetValue(hook) as Delegate ?? throw new McpException("挂钩没有可用的原函数委托。");

        STORES[observation.Id]    = store;
        ORIGINALS[observation.Id] = original;
        observation.Handler       = detour;
        observation.Address       = address;

        hook.GetType().GetMethod("Enable", BindingFlags.Instance | BindingFlags.Public)?.Invoke(hook, null);

        return hook;
    }

    /// <summary>
    /// 卸载挂钩。
    /// </summary>
    /// <param name="observationId">观察点 id。</param>
    /// <param name="hook">挂钩对象。</param>
    public static void Uninstall
    (
        string  observationId,
        object? hook
    )
    {
        ORIGINALS.TryRemove(observationId, out _);
        STORES.TryRemove(observationId, out _);

        if (hook is IDisposable disposable)
            disposable.Dispose();
    }

    /// <summary>
    /// 取回原函数委托。
    /// </summary>
    /// <param name="observationId">观察点 id。</param>
    /// <returns>原函数委托。</returns>
    public static Delegate GetOriginal
    (
        string observationId
    ) =>
        ORIGINALS.TryGetValue(observationId, out var original)
            ? original
            : throw new McpException($"观察点 {observationId} 的原函数尚未就绪。");

    /// <summary>
    /// 记录一次命中。
    /// </summary>
    /// <param name="observationId">观察点 id。</param>
    public static void RecordHit
    (
        string observationId
    )
    {
        if (!STORES.TryGetValue(observationId, out var store))
            return;

        try
        {
            store.Record(observationId, "hook", "命中", null, null);
        }
        catch (Exception)
        {
            // ignored
        }
    }

    private static Delegate BuildDetour
    (
        string observationId,
        Type   delegateType,
        Type   returnType,
        Type[] parameterTypes
    )
    {
        var dynamicMethod = new DynamicMethod
        (
            $"mcp_detour_{observationId}",
            returnType,
            parameterTypes,
            typeof(HookBridge).Module,
            true
        );

        var il = dynamicMethod.GetILGenerator();

        il.Emit(OpCodes.Ldstr, observationId);
        il.Emit(OpCodes.Call,  typeof(HookBridge).GetMethod(nameof(RecordHit))!);

        il.Emit(OpCodes.Ldstr,     observationId);
        il.Emit(OpCodes.Call,      typeof(HookBridge).GetMethod(nameof(GetOriginal))!);
        il.Emit(OpCodes.Castclass, delegateType);

        for (var index = 0; index < parameterTypes.Length; index++)
            il.Emit(OpCodes.Ldarg, index);

        il.Emit(OpCodes.Callvirt, delegateType.GetMethod("Invoke")!);
        il.Emit(OpCodes.Ret);

        return dynamicMethod.CreateDelegate(delegateType);
    }
}
