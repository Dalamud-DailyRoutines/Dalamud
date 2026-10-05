using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Dalamud;

/// <summary>
/// 观察点注册表与证据缓冲。证据带全局序号，可当游标拉取，也支持长轮询等待。
/// </summary>
internal sealed class ObservationStore
{
    private const int MAX_EVIDENCE = 4096;

    private readonly Lock                            gate         = new();
    private readonly List<EvidenceRecord>            evidence     = [];
    private readonly Dictionary<string, Observation> observations = new(StringComparer.Ordinal);
    private readonly List<Waiter>                    waiters      = [];
    private          long                            nextSequence;
    private          int                             nextObservationId;

    /// <summary>
    /// 生成下一个观察点 id。
    /// </summary>
    /// <returns>观察点 id。</returns>
    public string NextObservationId() => $"w{Interlocked.Increment(ref this.nextObservationId)}";

    /// <summary>
    /// 注册观察点。
    /// </summary>
    /// <param name="observation">观察点。</param>
    public void Add
    (
        Observation observation
    )
    {
        lock (this.gate)
            this.observations[observation.Id] = observation;
    }

    /// <summary>
    /// 取回观察点。
    /// </summary>
    /// <param name="id">观察点 id。</param>
    /// <returns>观察点，不存在时为 null。</returns>
    public Observation? Get
    (
        string id
    )
    {
        lock (this.gate)
            return this.observations.GetValueOrDefault(id);
    }

    /// <summary>
    /// 移除观察点。
    /// </summary>
    /// <param name="id">观察点 id。</param>
    /// <returns>被移除的观察点，不存在时为 null。</returns>
    public Observation? Remove
    (
        string id
    )
    {
        lock (this.gate)
        {
            if (!this.observations.Remove(id, out var observation))
                return null;

            observation.Active = false;
            return observation;
        }
    }

    /// <summary>
    /// 列出全部观察点。
    /// </summary>
    /// <returns>观察点序列。</returns>
    public IReadOnlyList<Observation> List()
    {
        lock (this.gate)
            return [.. this.observations.Values.OrderBy(observation => observation.Id, StringComparer.Ordinal)];
    }

    /// <summary>
    /// 记录一条证据。
    /// </summary>
    /// <param name="observationId">来源观察点。</param>
    /// <param name="mode">来源模式。</param>
    /// <param name="summary">一行摘要。</param>
    /// <param name="memoryHex">抓到的内存十六进制文本。</param>
    /// <param name="stack">托管调用栈文本。</param>
    public void Record
    (
        string  observationId,
        string  mode,
        string  summary,
        string? memoryHex,
        string? stack
    )
    {
        EvidenceRecord record;

        lock (this.gate)
        {
            this.nextSequence++;
            record = new EvidenceRecord(this.nextSequence, observationId, mode, summary, memoryHex, stack);

            if (this.evidence.Count >= MAX_EVIDENCE)
            {
                this.evidence.RemoveAt(0);

                if (this.observations.TryGetValue(observationId, out var overflowed))
                    overflowed.DroppedCount++;
            }

            this.evidence.Add(record);

            if (this.observations.TryGetValue(observationId, out var observation))
                observation.EvidenceCount++;
        }

        List<Waiter>? notified = null;

        lock (this.gate)
        {
            for (var index = this.waiters.Count - 1; index >= 0; index--)
            {
                var waiter = this.waiters[index];
                if (waiter.ObservationId is not null && !string.Equals(waiter.ObservationId, observationId, StringComparison.Ordinal))
                    continue;

                this.waiters.RemoveAt(index);
                (notified ??= []).Add(waiter);
            }
        }

        if (notified is null)
            return;

        foreach (var waiter in notified)
            waiter.Completion.TrySetResult(record);
    }

    /// <summary>
    /// 取出序号大于游标的证据。
    /// </summary>
    /// <param name="cursor">游标，取 0 表示从头。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <param name="observationId">只取某个观察点的证据。</param>
    /// <returns>证据序列。</returns>
    public IReadOnlyList<EvidenceRecord> Since
    (
        long    cursor,
        int     limit,
        string? observationId = null
    )
    {
        lock (this.gate)
        {
            return
            [
                .. this.evidence
                       .Where(record => record.Sequence > cursor)
                       .Where(record => observationId is null || string.Equals(record.ObservationId, observationId, StringComparison.Ordinal))
                       .Take(limit)
            ];
        }
    }

    /// <summary>
    /// 按序号取回单条证据。
    /// </summary>
    /// <param name="sequence">序号。</param>
    /// <returns>证据，不存在时为 null。</returns>
    public EvidenceRecord? Find
    (
        long sequence
    )
    {
        lock (this.gate)
            return this.evidence.FirstOrDefault(record => record.Sequence == sequence);
    }

    /// <summary>
    /// 清空证据缓冲。
    /// </summary>
    /// <returns>清空的条数。</returns>
    public int Clear()
    {
        lock (this.gate)
        {
            var count = this.evidence.Count;
            this.evidence.Clear();
            return count;
        }
    }

    /// <summary>
    /// 长轮询等待下一条证据。
    /// </summary>
    /// <param name="observationId">只等某个观察点的证据。</param>
    /// <param name="timeout">等待上限。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>收到的证据，超时返回 null。</returns>
    public async Task<EvidenceRecord?> WaitAsync
    (
        string?           observationId,
        TimeSpan          timeout,
        CancellationToken cancellationToken
    )
    {
        var waiter = new Waiter(observationId);

        lock (this.gate)
            this.waiters.Add(waiter);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        await using var registration = timeoutSource.Token.Register(() => waiter.Completion.TrySetResult(null));

        try
        {
            return await waiter.Completion.Task;
        }
        finally
        {
            lock (this.gate)
                this.waiters.Remove(waiter);
        }
    }

    private sealed class Waiter
    {
        public Waiter
        (
            string? observationId
        ) =>
            this.ObservationId = observationId;

        public string? ObservationId { get; }

        public TaskCompletionSource<EvidenceRecord?> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
