using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>control</c> 原语：列出线程、挂起与恢复线程。
/// </summary>
internal static class ControlTool
{
    private static readonly Lock                             GATE      = new();
    private static readonly ConcurrentDictionary<uint, nint> SUSPENDED = new();

    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: threads、pause、resume、state。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string action
    )
    {
        return action.ToLowerInvariant() switch
        {
            "threads" => ListThreads(),
            "pause"   => Pause(),
            "resume"  => Resume(),
            "state"   => State(),
            _         => throw new McpException($"不支持的操作 \"{action}\"，可用值为 threads、pause、resume、state。")
        };
    }

    private static string ListThreads()
    {
        var current = NativeApi.GetCurrentThreadId();
        var threads = new List<string>();

        foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
        {
            threads.Add
            (
                "{\"id\":" + thread.Id +
                ",\"state\":" + ValueFormatter.Format(thread.ThreadState.ToString(), 0) +
                ",\"waitReason\":" + ValueFormatter.Format(thread.WaitReason.ToString(), 0) +
                ",\"priority\":" + ValueFormatter.Format(thread.PriorityLevel.ToString(), 0) +
                ",\"isCurrent\":" + (thread.Id == current ? "true" : "false") +
                ",\"isSuspended\":" + (SUSPENDED.ContainsKey((uint)thread.Id) ? "true" : "false") +
                "}"
            );
        }

        var builder = new StringBuilder(1024);
        builder.Append("{\"currentThread\":").Append(current);
        builder.Append(",\"suspended\":").Append(SUSPENDED.Count);
        builder.Append(",\"threads\":[").Append(string.Join(',', threads)).Append("]}");
        return builder.ToString();
    }

    private static string Pause()
    {
        var current   = NativeApi.GetCurrentThreadId();
        var suspended = 0;

        lock (GATE)
        {
            foreach (ProcessThread thread in Process.GetCurrentProcess().Threads)
            {
                var id = (uint)thread.Id;
                if (id == current || SUSPENDED.ContainsKey(id))
                    continue;

                var handle = NativeApi.OpenThread
                (
                    NativeApi.THREAD_SUSPEND_RESUME | NativeApi.THREAD_GET_CONTEXT | NativeApi.THREAD_SET_CONTEXT | NativeApi.THREAD_QUERY_INFORMATION,
                    false,
                    id
                );

                if (handle == 0)
                    continue;

                if (NativeApi.SuspendThread(handle) == unchecked((int)0xFFFFFFFF))
                {
                    NativeApi.CloseHandle(handle);
                    continue;
                }

                SUSPENDED[id] = handle;
                suspended++;
            }
        }

        McpRuntimeTrace($"pause suspended={suspended}");

        return "{\"action\":\"pause\",\"suspended\":" + suspended + ",\"total\":" + SUSPENDED.Count + "}";
    }

    private static string Resume()
    {
        var resumed = 0;

        lock (GATE)
        {
            foreach (var (id, handle) in new List<KeyValuePair<uint, nint>>(SUSPENDED))
            {
                _ = NativeApi.ResumeThread(handle);
                NativeApi.CloseHandle(handle);
                SUSPENDED.TryRemove(id, out _);
                resumed++;
            }
        }

        McpRuntimeTrace($"resume resumed={resumed}");

        return "{\"action\":\"resume\",\"resumed\":" + resumed + ",\"total\":" + SUSPENDED.Count + "}";
    }

    private static string State()
    {
        var current = NativeApi.GetCurrentThreadId();
        var builder = new StringBuilder(256);

        builder.Append("{\"currentThread\":").Append(current);
        builder.Append(",\"suspendedThreads\":").Append(SUSPENDED.Count);
        builder.Append(",\"nativeOnly\":").Append(SUSPENDED.IsEmpty ? "false" : "true");
        builder.Append('}');
        return builder.ToString();
    }

    private static void McpRuntimeTrace
    (
        string message
    ) => MCPRuntime.Trace.Write("control", message);
}
