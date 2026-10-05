using System.Collections.Generic;

namespace Dalamud;

/// <summary>
/// 一次值搜索的会话。候选地址与上一次读到的数值留在进程内，跨请求只传会话 id。
/// </summary>
internal sealed class ScanSession
{
    /// <summary>
    /// 初始化 <see cref="ScanSession"/> 类的新实例。
    /// </summary>
    /// <param name="id">会话 id。</param>
    /// <param name="valueType">值的类型名。</param>
    /// <param name="candidates">候选地址。</param>
    /// <param name="values">与候选一一对应的上次读到的数值。</param>
    /// <param name="totalMatched">首次扫描命中的总数。</param>
    public ScanSession
    (
        string       id,
        string       valueType,
        List<nint>   candidates,
        List<double> values,
        int          totalMatched
    )
    {
        this.Id           = id;
        this.ValueType    = valueType;
        this.Candidates   = candidates;
        this.Values       = values;
        this.TotalMatched = totalMatched;
        this.CreatedAt    = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Gets 会话 id。
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets 值的类型名。
    /// </summary>
    public string ValueType { get; }

    /// <summary>
    /// Gets 候选地址列表。
    /// </summary>
    public List<nint> Candidates { get; }

    /// <summary>
    /// Gets 与候选一一对应的上次读到的数值。
    /// </summary>
    public List<double> Values { get; }

    /// <summary>
    /// Gets 首次扫描命中的总数。
    /// </summary>
    public int TotalMatched { get; }

    /// <summary>
    /// Gets 会话创建时间。
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    /// Gets or sets a value indicating whether the first scan stopped early because of the candidate cap.
    /// </summary>
    public bool Truncated { get; set; }
}
