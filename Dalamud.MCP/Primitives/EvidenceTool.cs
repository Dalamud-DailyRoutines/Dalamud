using System.Globalization;
using System.Text;
using System.Threading;
using Dalamud.Utility;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>evidence</c> 原语：按游标拉取观察点产生的证据，并支持长轮询等待。
/// </summary>
internal static class EvidenceTool
{
    /// <summary>
    /// 执行操作。
    /// </summary>
    /// <param name="action">操作类型: list、get、wait、clear。</param>
    /// <param name="cursor">游标，取序号大于该值的证据。</param>
    /// <param name="limit">最多返回条数。</param>
    /// <param name="sequence">get 时的证据序号。</param>
    /// <param name="observation">只关心某个观察点的证据。</param>
    /// <param name="timeoutSeconds">wait 的等待上限秒数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        long    cursor         = 0,
        int     limit          = 32,
        long    sequence       = 0,
        string? observation    = null,
        double  timeoutSeconds = 5
    )
    {
        var store = MCPRuntime.Observations;
        var page  = Math.Clamp(limit, 1, 500);

        switch (action.ToLowerInvariant())
        {
            case "list":
                return RenderList(store, cursor, page, observation);

            case "get":
            {
                var record = store.Find(sequence) ?? throw new McpException($"不存在序号为 {sequence} 的证据。");

                return Render(record);
            }

            case "wait":
            {
                var timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 0.1, 25));
                var record  = store.WaitAsync(observation, timeout, CancellationToken.None).GetResultSafely();

                return record is null
                           ? "{\"timedOut\":true}"
                           : Render(record);
            }

            case "clear":
                return "{\"cleared\":" + store.Clear() + "}";

            default:
                throw new McpException($"不支持的操作 \"{action}\"，可用值为 list、get、wait、clear。");
        }
    }

    private static string RenderList
    (
        ObservationStore store,
        long             cursor,
        int              limit,
        string?          observation
    )
    {
        var records = store.Since(cursor, limit, observation);
        var builder = new StringBuilder(2048);

        builder.Append("{\"cursor\":").Append(cursor);
        builder.Append(",\"count\":").Append(records.Count);
        builder.Append(",\"records\":[");

        for (var index = 0; index < records.Count; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append(Render(records[index]));
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string Render
    (
        EvidenceRecord record
    )
    {
        var builder = new StringBuilder(512);
        builder.Append("{\"sequence\":").Append(record.Sequence);
        builder.Append(",\"observation\":").Append(ValueFormatter.Format(record.ObservationId, 0));
        builder.Append(",\"mode\":").Append(ValueFormatter.Format(record.Mode,                 0));
        builder.Append(",\"summary\":").Append(ValueFormatter.Format(record.Summary,           0));
        builder.Append(",\"timestamp\":").Append
        (
            ValueFormatter.Format
            (
                record.Timestamp.ToString("O", CultureInfo.InvariantCulture),
                0
            )
        );

        if (record.MemoryHex is { } memory)
            builder.Append(",\"memory\":").Append(ValueFormatter.Format(memory, 0));

        if (record.Stack is { } stack)
            builder.Append(",\"stack\":").Append(ValueFormatter.Format(stack, 0));

        builder.Append('}');
        return builder.ToString();
    }
}
