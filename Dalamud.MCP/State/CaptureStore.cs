using System.Collections.Generic;
using System.Threading;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>限制总字节数和图像数量的截图缓存。</summary>
internal static class CaptureStore
{
    private static readonly Lock                              Gate   = new();
    private static readonly Dictionary<string, CapturedFrame> Frames = new(StringComparer.Ordinal);
    private static readonly Queue<string>                     Order  = new();
    private static          long                              bytes;

    public static void Add(CapturedFrame frame)
    {
        if (frame.Png.Length > 64 * 1024 * 1024)
            throw new McpException("单张截图超过 64 MiB 缓存预算，请缩小输出尺寸。");

        lock (Gate)
        {
            while (Order.Count > 0 && (Frames.Count >= 16 || bytes + frame.Png.Length > 64 * 1024 * 1024))
            {
                var removed = Frames[Order.Dequeue()];
                Frames.Remove(removed.Id);
                bytes -= removed.Png.Length;
            }

            Frames.Add(frame.Id, frame);
            Order.Enqueue(frame.Id);
            bytes += frame.Png.Length;
        }
    }

    public static CapturedFrame Get(string id)
    {
        lock (Gate)
            return Frames.TryGetValue(id, out var frame) ?
                       frame :
                       throw new McpException("截图引用不存在或已被淘汰，请重新截图。");
    }

    public static void Clear()
    {
        lock (Gate)
        {
            Frames.Clear();
            Order.Clear();
            bytes = 0;
        }
    }
}
