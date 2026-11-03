using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using HarmonyLib;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>同一目标共享补丁，独立管理观察点并记录返回与异常。</summary>
internal static class ManagedHookManager
{
    private static readonly Harmony Harmony = new("dalamud.mcp");
    private static readonly Lock Gate = new();
    private static readonly Dictionary<string, MethodInfo> Targets = new(StringComparer.Ordinal);

    public static void Patch(Observation observation, MethodInfo target)
    {
        lock (Gate)
        {
            if (!Targets.Values.Contains(target))
            {
                var postfix = target.ReturnType == typeof(void) ? nameof(PostfixVoid) : nameof(PostfixResult);
                try
                {
                    Harmony.Patch(target,
                        postfix: new HarmonyMethod(typeof(ManagedHookManager).GetMethod(postfix, BindingFlags.Static | BindingFlags.NonPublic)!),
                        finalizer: new HarmonyMethod(typeof(ManagedHookManager).GetMethod(nameof(Finalizer), BindingFlags.Static | BindingFlags.NonPublic)!));
                }
                catch
                {
                    Harmony.Unpatch(target, HarmonyPatchType.All, Harmony.Id);
                    throw;
                }
            }

            Targets.Add(observation.Id, target);
        }
    }

    public static bool Unpatch(string observationId)
    {
        lock (Gate)
        {
            if (!Targets.Remove(observationId, out var target))
                return false;

            if (!Targets.Values.Contains(target))
                Harmony.Unpatch(target, HarmonyPatchType.All, Harmony.Id);

            return true;
        }
    }

    public static void Clear()
    {
        lock (Gate)
        {
            foreach (var target in Targets.Values.Distinct())
                Harmony.Unpatch(target, HarmonyPatchType.All, Harmony.Id);

            Targets.Clear();
        }
    }

    private static void PostfixVoid(MethodBase __originalMethod, object[] __args) => Record(__originalMethod, __args, null, null);

    private static void PostfixResult(MethodBase __originalMethod, object[] __args, object? __result) => Record(__originalMethod, __args, __result, null);

    private static Exception? Finalizer(MethodBase __originalMethod, object[] __args, Exception? __exception)
    {
        if (__exception is not null)
            Record(__originalMethod, __args, null, __exception);

        return __exception;
    }

    private static void Record(MethodBase method, object[] arguments, object? returned, Exception? exception)
    {
        try
        {
            string[] ids;
            lock (Gate)
                ids = Targets.Where(entry => entry.Value == method).Select(entry => entry.Key).ToArray();

            if (ids.Length == 0)
                return;

            var details = new
            {
                method = method.ToString(),
                arguments = Array.ConvertAll(arguments, argument => ValueFormatter.Snapshot(argument)),
                returned = ValueFormatter.Snapshot(returned),
                exception = exception?.Message,
                threadId = Environment.CurrentManagedThreadId
            };
            foreach (var id in ids)
                MCPRuntime.Observations.Record(id, "managedhook", exception is null ? "托管方法返回" : "托管方法异常", null, null, details);
        }
        catch (Exception)
        {
            // ignored
        }
    }
}
