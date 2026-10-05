namespace Dalamud;

/// <summary>
/// 一条证据：某次命中时抓到的现场摘要。
/// </summary>
internal sealed class EvidenceRecord
{
    /// <summary>
    /// 初始化 <see cref="EvidenceRecord"/> 类的新实例。
    /// </summary>
    /// <param name="sequence">全局序号。</param>
    /// <param name="observationId">来源观察点。</param>
    /// <param name="mode">来源模式。</param>
    /// <param name="summary">一行摘要。</param>
    /// <param name="memoryHex">抓到的内存十六进制文本，无则为 null。</param>
    /// <param name="stack">托管调用栈文本，无则为 null。</param>
    public EvidenceRecord
    (
        long    sequence,
        string  observationId,
        string  mode,
        string  summary,
        string? memoryHex,
        string? stack
    )
    {
        this.Sequence      = sequence;
        this.ObservationId = observationId;
        this.Mode          = mode;
        this.Summary       = summary;
        this.MemoryHex     = memoryHex;
        this.Stack         = stack;
        this.Timestamp     = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Gets 全局序号，可当作游标使用。
    /// </summary>
    public long Sequence { get; }

    /// <summary>
    /// Gets 来源观察点 id。
    /// </summary>
    public string ObservationId { get; }

    /// <summary>
    /// Gets 来源模式。
    /// </summary>
    public string Mode { get; }

    /// <summary>
    /// Gets 一行摘要。
    /// </summary>
    public string Summary { get; }

    /// <summary>
    /// Gets 抓到的内存十六进制文本。
    /// </summary>
    public string? MemoryHex { get; }

    /// <summary>
    /// Gets 托管调用栈文本。
    /// </summary>
    public string? Stack { get; }

    /// <summary>
    /// Gets 记录时间。
    /// </summary>
    public DateTimeOffset Timestamp { get; }
}
