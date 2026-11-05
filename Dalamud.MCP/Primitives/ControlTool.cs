using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;

namespace Dalamud;

/// <summary>进程内调试状态与线程目录。</summary>
internal static class ControlTool
{
    public enum Operation
    {
        Threads, State
    }

    /// <summary>读取状态。进程内服务器不提供全进程线程挂起。</summary>
    public static string Run([Description("操作：threads 列出线程；state 返回服务器状态。不支持全进程暂停。")] Operation action)
    {
        if (action == Operation.State)
        {
            return JsonSerializer.Serialize
            (
                new
                {
                    running        = MCPRuntime.IsRunning,
                    port           = MCPRuntime.Port,
                    processId      = Environment.ProcessId,
                    observations   = MCPRuntime.Observations.List().Count,
                    scans          = MCPRuntime.ScanSessions.Count,
                    pauseSupported = false
                }
            );
        }

        if (action != Operation.Threads)
            throw new ArgumentException("可用操作：threads、state。全进程暂停必须使用进程外调试器。", nameof(action));

        using var process = Process.GetCurrentProcess();
        var threads = process.Threads.Cast<ProcessThread>().Select
        (thread =>
            {
                using (thread)
                {
                    var state = thread.ThreadState;
                    return new
                    {
                        id    = thread.Id,
                        state = state.ToString(),
                        waitReason = state == ThreadState.Wait ?
                                         thread.WaitReason.ToString() :
                                         null
                    };
                }
            }
        ).ToArray();

        return JsonSerializer.Serialize(new { threads });
    }
}
