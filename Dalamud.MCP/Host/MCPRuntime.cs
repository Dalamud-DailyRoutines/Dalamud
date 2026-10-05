using System.Collections.Concurrent;
using System.Threading;

namespace Dalamud;

/// <summary>
/// 进程内共享的运行时状态：引用表、trace 文件、扫描会话、观察点与挂钩。
/// </summary>
internal static class MCPRuntime
{
    private static MemoryWatcher? watcher;
    private static int            nextScanSessionId;

    /// <summary>Gets 引用表。</summary>
    public static ReferenceTable References { get; } = new();

    /// <summary>Gets trace 文件。</summary>
    public static TraceLog Trace { get; } = new();

    /// <summary>Gets 活跃的扫描会话。</summary>
    public static ConcurrentDictionary<string, ScanSession> ScanSessions { get; } = new(StringComparer.Ordinal);

    /// <summary>Gets 观察点仓库。</summary>
    public static ObservationStore Observations { get; } = new();

    /// <summary>Gets 已安装的原生挂钩。</summary>
    public static ConcurrentDictionary<string, object> Hooks { get; } = new(StringComparer.Ordinal);

    /// <summary>Gets or sets 监听端口。</summary>
    public static int Port { get; set; }

    /// <summary>Gets or sets a value indicating whether the MCP server is listening.</summary>
    public static bool IsRunning { get; set; }

    /// <summary>Gets or sets 最近一次启动失败的原因。</summary>
    public static string? LastError { get; set; }

    /// <summary>
    /// 生成下一个扫描会话 id。
    /// </summary>
    /// <returns>会话 id。</returns>
    public static string NextScanSessionId() => $"q{Interlocked.Increment(ref nextScanSessionId)}";

    /// <summary>
    /// 确保内存轮询线程已启动。只在确实要监视内存时调用。
    /// </summary>
    public static void EnsureWatcher()
    {
        if (watcher is not null)
            return;

        watcher = new MemoryWatcher(Observations);
        watcher.Start();
    }

    /// <summary>
    /// 停止观察引擎并释放全部挂钩。
    /// </summary>
    public static void Shutdown()
    {
        watcher?.Dispose();
        watcher = null;

        foreach (var (id, hook) in Hooks)
            HookBridge.Uninstall(id, hook);

        Hooks.Clear();
        ManagedHookManager.Clear();
    }
}
