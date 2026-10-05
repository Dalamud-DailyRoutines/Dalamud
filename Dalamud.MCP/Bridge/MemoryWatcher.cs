using System.Threading;

namespace Dalamud;

/// <summary>
/// 按各自间隔轮询 memwatch 观察点，字节内容变化时写入一条证据。
/// </summary>
internal sealed class MemoryWatcher : IDisposable
{
    private const int TICK_MILLISECONDS = 10;

    private readonly ObservationStore        store;
    private readonly CancellationTokenSource cancellation = new();
    private readonly Thread                  worker;
    private          bool                    disposed;

    /// <summary>
    /// 初始化 <see cref="MemoryWatcher"/> 类的新实例。
    /// </summary>
    /// <param name="store">观察点仓库。</param>
    public MemoryWatcher
    (
        ObservationStore store
    )
    {
        this.store = store;
        this.worker = new Thread(this.Loop)
        {
            IsBackground = true,
            Name         = "dalamud-mcp-memwatch"
        };
    }

    /// <summary>
    /// 启动轮询线程。
    /// </summary>
    public void Start() => this.worker.Start();

    /// <inheritdoc/>
    public void Dispose()
    {
        if (this.disposed)
            return;

        this.disposed = true;
        this.cancellation.Cancel();
        this.worker.Join(TimeSpan.FromSeconds(1));
        this.cancellation.Dispose();
    }

    private void Loop()
    {
        while (!this.cancellation.IsCancellationRequested)
        {
            var now = Environment.TickCount64;

            foreach (var observation in this.store.List())
            {
                if (!observation.Active || observation.Mode != "memwatch" || observation.Address == 0)
                    continue;

                if (observation.LastPollTicks != 0 && now - observation.LastPollTicks < observation.PollIntervalMs)
                    continue;

                observation.LastPollTicks = now;
                this.Poll(observation);
            }

            this.cancellation.Token.WaitHandle.WaitOne(TICK_MILLISECONDS);
        }
    }

    private void Poll
    (
        Observation observation
    )
    {
        try
        {
            var bytes    = MemoryAccess.ReadBytes(observation.Address, observation.CaptureBytes);
            var previous = observation.LastBytes;
            observation.LastBytes = bytes;

            if (previous is null || previous.AsSpan().SequenceEqual(bytes))
                return;

            var summary = string.Create
            (
                System.Globalization.CultureInfo.InvariantCulture,
                $"{MemoryScanner.FormatAddress(observation.Address)} {Convert.ToHexString(previous)} -> {Convert.ToHexString(bytes)}"
            );

            if (observation.ValueType is { } valueType)
            {
                try
                {
                    var numeric = MemoryScanner.ReadNumericAt(observation.Address, valueType);
                    summary += $" value={numeric}";
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            this.store.Record(observation.Id, "memwatch", summary, Convert.ToHexString(bytes), null);
        }
        catch (Exception exception)
        {
            this.store.Record(observation.Id, "memwatch", "读取失败: " + exception.Message, null, null);
            observation.Active = false;
        }
    }
}
