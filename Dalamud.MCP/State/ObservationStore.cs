using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Dalamud;

/// <summary>带保留边界和原子游标等待的有界证据仓库。</summary>
internal sealed class ObservationStore
{
    private const    int                             MAX_EVIDENCE = 4096;
    private readonly Lock                            gate         = new();
    private readonly Queue<EvidenceRecord>           evidence     = new();
    private readonly Dictionary<string, Observation> observations = new(StringComparer.Ordinal);
    private          TaskCompletionSource            changed      = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private          long                            nextSequence;
    private          long                            discardedThrough;
    private          int                             nextObservationId;

    public string NextObservationId() => $"w{Interlocked.Increment(ref this.nextObservationId)}";

    public void Add(Observation observation)
    {
        lock (this.gate)
            this.observations.Add(observation.Id, observation);
    }

    public Observation? Get(string id)
    {
        lock (this.gate)
            return this.observations.GetValueOrDefault(id);
    }

    public Observation? Remove(string id)
    {
        lock (this.gate)
        {
            if (!this.observations.Remove(id, out var observation))
                return null;

            observation.Active = false;
            return observation;
        }
    }

    public IReadOnlyList<Observation> List()
    {
        lock (this.gate)
            return [.. this.observations.Values.OrderBy(observation => observation.Id, StringComparer.Ordinal)];
    }

    public void Record(string observationId, string mode, string summary, string? memoryHex, string? stack, object? details = null)
    {
        TaskCompletionSource signal;

        lock (this.gate)
        {
            if (!this.observations.TryGetValue(observationId, out var observation) || !observation.Active)
                return;

            if (!observation.ShouldCapture())
                return;

            var record = new EvidenceRecord(++this.nextSequence, observationId, mode, summary, memoryHex, stack)
            {
                Details = details
            };

            if (this.evidence.Count >= MAX_EVIDENCE)
            {
                var removed = this.evidence.Dequeue();
                this.discardedThrough = removed.Sequence;
                if (this.observations.TryGetValue(removed.ObservationId, out var source))
                    source.DroppedCount++;
            }

            this.evidence.Enqueue(record);
            observation.EvidenceCount++;
            signal       = this.changed;
            this.changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        signal.TrySetResult();
    }

    public object Read(long cursor, int limit, string? observationId)
    {
        lock (this.gate)
        {
            var records = this.Since(cursor, limit, observationId);
            var next = records.Count == limit ?
                           records[^1].Sequence :
                           this.nextSequence;
            return new
            {
                cursor,
                nextCursor = Math.Max(cursor, next),
                oldestSequence = this.evidence.TryPeek(out var first) ?
                                     first.Sequence :
                                     this.nextSequence + 1,
                latestSequence = this.nextSequence,
                gap            = cursor < this.discardedThrough,
                records
            };
        }
    }

    public IReadOnlyList<EvidenceRecord> Since(long cursor, int limit, string? observationId = null)
    {
        lock (this.gate)
            return [.. this.evidence.Where(record => record.Sequence > cursor && (observationId is null || record.ObservationId == observationId)).Take(limit)];
    }

    public EvidenceRecord? Find(long sequence)
    {
        lock (this.gate)
            return this.evidence.FirstOrDefault(record => record.Sequence == sequence);
    }

    public int Clear()
    {
        lock (this.gate)
        {
            var count = this.evidence.Count;
            this.evidence.Clear();
            this.discardedThrough = this.nextSequence;
            return count;
        }
    }

    public async Task<bool> WaitAsync(long cursor, string? observationId, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        while (true)
        {
            Task signal;

            lock (this.gate)
            {
                if (this.evidence.Any(record => record.Sequence > cursor && (observationId is null || record.ObservationId == observationId)))
                    return true;

                signal = this.changed.Task;
            }

            try
            {
                await signal.WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return false;
            }
        }
    }
}
