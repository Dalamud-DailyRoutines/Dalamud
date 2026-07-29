using System.Diagnostics;
using System.IO;

using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Storage;

using Serilog;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying configuration info.
/// </summary>
internal class VfsWidget : IDataWindowWidget
{
    private int numBytes = 1024;
    private int reps = 1;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["vfs"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "VFS 性能";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var service = Service<ReliableFileStorage>.Get();
        var dalamud = Service<Dalamud>.Get();

        ImGui.InputInt("字节数"u8, ref this.numBytes);
        ImGui.InputInt("重复次数"u8, ref this.reps);

        var path = Path.Combine(dalamud.StartInfo.WorkingDirectory!, "test.bin");

        if (ImGui.Button("写入"u8))
        {
            Log.Information("=== 正在写入 ===");
            var data = new byte[this.numBytes];
            var stopwatch = new Stopwatch();
            var acc = 0L;

            for (var i = 0; i < this.reps; i++)
            {
                stopwatch.Restart();
                service.WriteAllBytesAsync(path, data).GetAwaiter().GetResult();
                stopwatch.Stop();
                acc += stopwatch.ElapsedMilliseconds;
                Log.Information("第 {Turn} 次耗时 {Ms} ms", i, stopwatch.ElapsedMilliseconds);
            }

            Log.Information("总计耗时 {Ms} ms", acc);
        }

        if (ImGui.Button("读取"u8))
        {
            Log.Information("=== 正在读取 ===");
            var stopwatch = new Stopwatch();
            var acc = 0L;

            for (var i = 0; i < this.reps; i++)
            {
                stopwatch.Restart();
                service.ReadAllBytesAsync(path).GetAwaiter().GetResult();
                stopwatch.Stop();
                acc += stopwatch.ElapsedMilliseconds;
                Log.Information("第 {Turn} 次耗时 {Ms} ms", i, stopwatch.ElapsedMilliseconds);
            }

            Log.Information("总计耗时 {Ms} ms", acc);
        }

        if (ImGui.Button("测试配置"u8))
        {
            var config = Service<DalamudConfiguration>.Get();

            Log.Information("=== 正在读取 ===");
            var stopwatch = new Stopwatch();
            var acc = 0L;

            for (var i = 0; i < this.reps; i++)
            {
                stopwatch.Restart();
                config.ForceSave();
                stopwatch.Stop();
                acc += stopwatch.ElapsedMilliseconds;
                Log.Information("第 {Turn} 次耗时 {Ms} ms", i, stopwatch.ElapsedMilliseconds);
            }

            Log.Information("总计耗时 {Ms} ms", acc);
        }
    }
}
