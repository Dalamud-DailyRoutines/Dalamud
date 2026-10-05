using System.Collections.Concurrent;
using System.Threading;

namespace Dalamud;

/// <summary>
/// 在无状态 HTTP 传输之上维持跨请求可引用的托管对象与原生指针。
/// </summary>
internal sealed class ReferenceTable
{
    private const int MAX_OBJECTS = 4096;

    private readonly ConcurrentDictionary<string, WeakReference> objects      = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string>                     objectOrder  = new();
    private readonly ConcurrentDictionary<string, nint>          pointers     = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string>                     pointerOrder = new();
    private          int                                         nextObjectId;
    private          int                                         nextPointerId;

    /// <summary>
    /// 注册一个托管对象。
    /// </summary>
    /// <param name="value">要注册的对象。</param>
    /// <returns>可用于后续请求的引用 id。</returns>
    public string TrackObject
    (
        object value
    )
    {
        this.TrimObjects();

        var id = $"o{Interlocked.Increment(ref this.nextObjectId)}";
        this.objects[id] = new WeakReference(value);
        this.objectOrder.Enqueue(id);
        return id;
    }

    /// <summary>
    /// 注册一个原生指针。
    /// </summary>
    /// <param name="address">要注册的地址。</param>
    /// <returns>可用于后续请求的引用 id。</returns>
    public string TrackPointer
    (
        nint address
    )
    {
        this.TrimPointers();

        var id = $"p{Interlocked.Increment(ref this.nextPointerId)}";
        this.pointers[id] = address;
        this.pointerOrder.Enqueue(id);
        return id;
    }

    /// <summary>
    /// 按引用 id 取回托管对象。
    /// </summary>
    /// <param name="id">引用 id。</param>
    /// <param name="value">取回的对象。</param>
    /// <returns>是否取回成功。</returns>
    public bool TryGetObject
    (
        string      id,
        out object? value
    )
    {
        value = null;

        if (!this.objects.TryGetValue(id, out var reference))
            return false;

        value = reference.Target;
        return value is not null;
    }

    /// <summary>
    /// 按引用 id 取回原生指针。
    /// </summary>
    /// <param name="id">引用 id。</param>
    /// <param name="address">取回的地址。</param>
    /// <returns>是否取回成功。</returns>
    public bool TryGetPointer
    (
        string   id,
        out nint address
    ) => this.pointers.TryGetValue(id, out address);

    private void TrimObjects()
    {
        while (this.objects.Count >= MAX_OBJECTS && this.objectOrder.TryDequeue(out var oldest))
            this.objects.TryRemove(oldest, out _);

        while (this.objectOrder.Count > MAX_OBJECTS)
            this.objectOrder.TryDequeue(out _);
    }

    private void TrimPointers()
    {
        while (this.pointers.Count >= MAX_OBJECTS && this.pointerOrder.TryDequeue(out var oldest))
            this.pointers.TryRemove(oldest, out _);

        while (this.pointerOrder.Count > MAX_OBJECTS)
            this.pointerOrder.TryDequeue(out _);
    }
}
