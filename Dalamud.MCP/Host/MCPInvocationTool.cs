using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Dalamud;

/// <summary>为工具调用提供操作编号、结构化结果及执行前后的流水。</summary>
internal sealed class MCPInvocationTool
(
    McpServerTool inner
) : McpServerTool
{
    public override Tool ProtocolTool => inner.ProtocolTool;

    public override IReadOnlyList<object> Metadata => inner.Metadata;

    public override async ValueTask<CallToolResult> InvokeAsync(RequestContext<CallToolRequestParams> request, CancellationToken cancellationToken = default)
    {
        var operation   = Guid.NewGuid().ToString("N");
        var started     = Stopwatch.GetTimestamp();
        var recordTrace = !string.Equals(this.ProtocolTool.Name, "trace", StringComparison.Ordinal);
        if (recordTrace)
            MCPRuntime.Trace.Write("begin", JsonSerializer.Serialize(new { operation, tool = this.ProtocolTool.Name, arguments = request.Params?.Arguments }));

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var       result  = await inner.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
            var       text    = result.Content.OfType<TextContentBlock>().FirstOrDefault()?.Text;
            JsonNode? payload = null;

            if (text is not null)
            {
                try
                {
                    payload = JsonNode.Parse(text);
                }
                catch (JsonException)
                {
                    payload = JsonValue.Create(text);
                }
            }

            var envelope = new JsonObject
            {
                ["operation"] = operation,
                ["status"] = result.IsError == true ?
                                 "failed" :
                                 "completed",
                ["sharedRuntime"] = true,
                ["result"]        = payload
            };
            result.StructuredContent = JsonSerializer.SerializeToElement(envelope);
            result.Content           = [new TextContentBlock { Text = envelope.ToJsonString() }, .. result.Content.Where(block => block is not TextContentBlock)];
            if (recordTrace)
                MCPRuntime.Trace.Write
                (
                    result.IsError == true ?
                        "failed" :
                        "completed",
                    operation,
                    Stopwatch.GetElapsedTime(started).TotalMilliseconds
                );
            return result;
        }
        catch (Exception exception)
        {
            if (recordTrace)
                MCPRuntime.Trace.Write
                (
                    "failed",
                    JsonSerializer.Serialize(new { operation, error = exception.GetBaseException().Message }),
                    Stopwatch.GetElapsedTime(started).TotalMilliseconds
                );
            var envelope = new
            {
                operation, status = exception is OperationCanceledException ?
                                        "cancelled" :
                                        "failed",
                sharedRuntime = true,
                error         = exception.GetBaseException().Message, effects = "already_started_operations_may_have_completed"
            };
            var json = JsonSerializer.SerializeToElement(envelope);
            return new CallToolResult
            {
                IsError           = true,
                StructuredContent = json,
                Content           = [new TextContentBlock { Text = json.GetRawText() }]
            };
        }
    }
}
