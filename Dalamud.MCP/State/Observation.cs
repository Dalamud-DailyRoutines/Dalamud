namespace Dalamud;

/// <summary>
/// 一个观察点：监视某处内存的变化，或订阅某个托管事件。
/// </summary>
internal sealed class Observation
{
    /// <summary>
    /// 初始化 <see cref="Observation"/> 类的新实例。
    /// </summary>
    /// <param name="id">观察点 id。</param>
    /// <param name="mode">模式，memwatch 或 hostevent。</param>
    /// <param name="target">memwatch 的地址文本，或 hostevent 的对象描述。</param>
    /// <param name="pollIntervalMs">memwatch 的轮询间隔毫秒数。</param>
    /// <param name="captureBytes">memwatch 每次抓取的字节数。</param>
    public Observation
    (
        string id,
        string mode,
        string target,
        int    pollIntervalMs,
        int    captureBytes
    )
    {
        this.Id             = id;
        this.Mode           = mode;
        this.Target         = target;
        this.PollIntervalMs = pollIntervalMs;
        this.CaptureBytes   = captureBytes;
        this.CreatedAt      = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Gets 观察点 id。
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets 模式。
    /// </summary>
    public string Mode { get; }

    /// <summary>
    /// Gets 目标描述。
    /// </summary>
    public string Target { get; }

    /// <summary>
    /// Gets 轮询间隔毫秒数。
    /// </summary>
    public int PollIntervalMs { get; }

    /// <summary>
    /// Gets 每次抓取的字节数。
    /// </summary>
    public int CaptureBytes { get; }

    /// <summary>
    /// Gets 创建时间。
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    /// Gets or sets memwatch 的被监视地址。
    /// </summary>
    public nint Address { get; set; }

    /// <summary>
    /// Gets or sets memwatch 的值类型名，可省略。
    /// </summary>
    public string? ValueType { get; set; }

    /// <summary>
    /// Gets or sets hostevent 的事件源对象。
    /// </summary>
    public object? Source { get; set; }

    /// <summary>
    /// Gets or sets hostevent 的事件名。
    /// </summary>
    public string? EventName { get; set; }

    /// <summary>
    /// Gets or sets hostevent 绑定用的委托，解除订阅时需要同一个实例。
    /// </summary>
    public Delegate? Handler { get; set; }

    /// <summary>
    /// Gets or sets 已记录的证据条数。
    /// </summary>
    public int EvidenceCount { get; set; }

    /// <summary>
    /// Gets or sets 因缓冲上限被丢弃的证据条数。
    /// </summary>
    public int DroppedCount { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the observation is still active.
    /// </summary>
    public bool Active { get; set; } = true;

    /// <summary>
    /// Gets or sets 上一次读到的原始字节，用于变化检测。
    /// </summary>
    public byte[]? LastBytes { get; set; }

    /// <summary>
    /// Gets or sets 上一次轮询的时间戳。
    /// </summary>
    public long LastPollTicks { get; set; }
}
