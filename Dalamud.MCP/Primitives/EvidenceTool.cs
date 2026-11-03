using System.ComponentModel;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>按游标读取和等待结构化运行时证据。</summary>
internal static class EvidenceTool
{
    public enum Operation
    {
        List,
        Get,
        Wait,
        Clear
    }

    public static async Task<string> Run
    (
        [Description("list 分页读取；get 读取指定序号；wait 从游标起等待并返回一页；clear 清空共享证据。")]
        Operation action,
        [Description("上次响应的 nextCursor；0 表示从保留记录开始。")]
        long cursor = 0,
        int                                       limit             = 32,
        long                                      sequence          = 0,
        string?                                   observation       = null,
        [Description("等待秒数，范围 0.1 至 15。")] double timeoutSeconds    = 5,
        CancellationToken                         cancellationToken = default
    )
    {
        var store = MCPRuntime.Observations;
        if (cursor < 0)
            throw new McpException("cursor 不能为负数。");

        switch (action)
        {
            case Operation.List:
                return JsonSerializer.Serialize(store.Read(cursor, Math.Clamp(limit, 1, 256), observation));
            case Operation.Get:
                return JsonSerializer.Serialize(store.Find(sequence) ?? throw new McpException($"证据 {sequence} 不存在或已被淘汰。"));
            case Operation.Wait:
                var available = await store.WaitAsync
                                    (cursor, observation, TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 0.1, 15)), cancellationToken).ConfigureAwait(false);
                return JsonSerializer.Serialize(new { timedOut = !available, page = store.Read(cursor, Math.Clamp(limit, 1, 256), observation) });
            case Operation.Clear:
                return JsonSerializer.Serialize(new { cleared = store.Clear() });
            default:
                throw new McpException("未知证据操作。");
        }
    }
}
