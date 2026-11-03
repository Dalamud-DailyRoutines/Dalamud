using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>可显式释放的有界强引用表，已有引用不会被自动淘汰。</summary>
internal sealed class ReferenceTable
{
    private const    int                        MAX_OBJECTS = 4096;
    private readonly Lock                       gate        = new();
    private readonly Dictionary<string, object> objects     = new(StringComparer.Ordinal);
    private readonly Dictionary<object, string> identities  = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<string, nint>   pointers    = new(StringComparer.Ordinal);
    private          int                        nextObjectId;
    private          int                        nextPointerId;

    public string TrackObject(object value)
    {
        lock (this.gate)
        {
            if (this.identities.TryGetValue(value, out var existing))
                return existing;

            if (this.objects.Count >= MAX_OBJECTS)
                throw new McpException("引用表已满，请使用 object_access release 释放引用。");

            var id = $"o{++this.nextObjectId}";
            this.objects.Add(id, value);
            this.identities.Add(value, id);
            return id;
        }
    }

    public string TrackPointer(nint address)
    {
        lock (this.gate)
        {
            if (this.pointers.Count >= MAX_OBJECTS)
                throw new McpException("指针引用表已满，请释放引用。");

            var id = $"p{++this.nextPointerId}";
            this.pointers.Add(id, address);
            return id;
        }
    }

    public bool TryGetObject(string id, out object? value)
    {
        lock (this.gate)
            return this.objects.TryGetValue(id, out value);
    }

    public object GetObject(string id)
    {
        lock (this.gate)
            return this.objects.TryGetValue(id, out var value) ?
                       value :
                       throw new McpException($"引用 {id} 不存在或已释放，请重新读取目标。");
    }

    public bool TryGetPointer(string id, out nint address)
    {
        lock (this.gate)
            return this.pointers.TryGetValue(id, out address);
    }

    public bool Release(string id)
    {
        lock (this.gate)
        {
            if (this.objects.Remove(id, out var value))
            {
                this.identities.Remove(value);
                return true;
            }

            return this.pointers.Remove(id);
        }
    }

    public void Clear()
    {
        lock (this.gate)
        {
            this.objects.Clear();
            this.identities.Clear();
            this.pointers.Clear();
        }
    }

    public static bool IsObjectReference(string value) =>
        value.Length > 1 && value[0] == 'o' && int.TryParse(value.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out _);
}
