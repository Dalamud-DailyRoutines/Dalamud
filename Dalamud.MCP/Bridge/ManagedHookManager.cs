using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Text;
using HarmonyLib;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 用 Harmony 给托管方法加前缀，命中时按方法反查观察点并记录证据。
/// </summary>
internal static class ManagedHookManager
{
    private static readonly Harmony                                  HARMONY = new("dalamud.mcp");
    private static readonly ConcurrentDictionary<string, MethodBase> TARGETS = new(StringComparer.Ordinal);

    /// <summary>
    /// 给托管方法安装前缀。
    /// </summary>
    /// <param name="observation">观察点。</param>
    /// <param name="target">目标方法。</param>
    public static void Patch
    (
        Observation observation,
        MethodBase  target
    )
    {
        var prefix = typeof(ManagedHookManager).GetMethod(nameof(Prefix), BindingFlags.Static | BindingFlags.NonPublic) ?? throw new McpException("找不到前缀方法。");

        var processor = HARMONY.CreateProcessor(target);
        processor.AddPrefix(new HarmonyMethod(prefix));
        processor.Patch();

        TARGETS[observation.Id] = target;
        observation.Source      = target;
    }

    /// <summary>
    /// 移除某个观察点的前缀。
    /// </summary>
    /// <param name="observationId">观察点 id。</param>
    /// <returns>是否移除了订阅。</returns>
    public static bool Unpatch
    (
        string observationId
    )
    {
        if (!TARGETS.TryRemove(observationId, out var target))
            return false;

        HARMONY.Unpatch(target, HarmonyPatchType.All, HARMONY.Id);
        return true;
    }

    /// <summary>
    /// 移除全部前缀。
    /// </summary>
    public static void Clear()
    {
        foreach (var id in TARGETS.Keys.ToArray())
            Unpatch(id);
    }

    private static void Prefix
    (
        MethodBase __originalMethod,
        object[]   __args
    )
    {
        var observationId = FindObservationId(__originalMethod);
        if (observationId is null)
            return;

        var builder = new StringBuilder(128);
        builder.Append("method=").Append(__originalMethod.DeclaringType?.Name).Append('.').Append(__originalMethod.Name);

        for (var index = 0; index < __args.Length; index++)
        {
            builder.Append(" arg").Append(index).Append('=');
            builder.Append(ValueFormatter.Format(__args[index], 1));
        }

        try
        {
            MCPRuntime.Observations.Record(observationId, "managedhook", builder.ToString(), null, null);
        }
        catch (Exception)
        {
            // ignored
        }
    }

    private static string? FindObservationId
    (
        MethodBase method
    )
    {
        foreach (var entry in TARGETS)
        {
            if (entry.Value == method || entry.Value.Equals(method))
                return entry.Key;
        }

        foreach (var entry in TARGETS)
        {
            if (string.Equals(entry.Value.Name, method.Name, StringComparison.Ordinal) && entry.Value.DeclaringType == method.DeclaringType)
            {
                return entry.Key;
            }
        }

        return null;
    }
}
