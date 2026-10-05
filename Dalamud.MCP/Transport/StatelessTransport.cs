using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using ModelContextProtocol.Protocol;

namespace Dalamud;

/// <summary>
/// 一次 HTTP 请求对应一个会话的无状态传输实现。
/// </summary>
internal sealed class StatelessTransport : TransportBase
{
    private readonly Channel<JsonRpcMessage> outbound = Channel.CreateUnbounded<JsonRpcMessage>();

    /// <summary>
    /// 初始化 <see cref="StatelessTransport"/> 类的新实例。
    /// </summary>
    public StatelessTransport()
        : base("dalamud-mcp-stateless", null) =>
        this.SetConnected();

    /// <inheritdoc/>
    public override Task SendMessageAsync
    (
        JsonRpcMessage    message,
        CancellationToken cancellationToken = default
    )
        => this.outbound.Writer.WriteAsync(message, cancellationToken).AsTask();

    /// <inheritdoc/>
    public override ValueTask DisposeAsync()
    {
        this.SetDisconnected();
        this.outbound.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// 把入站消息投递给服务器。
    /// </summary>
    /// <param name="message">入站消息。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>投递任务。</returns>
    public Task DeliverAsync
    (
        JsonRpcMessage    message,
        CancellationToken cancellationToken
    )
        => this.WriteMessageAsync(message, cancellationToken);

    /// <summary>
    /// 读取一条出站消息。
    /// </summary>
    /// <param name="timeout">等待上限。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>出站消息，超时或通道结束时返回 null。</returns>
    public async Task<JsonRpcMessage?> ReadOutboundAsync
    (
        TimeSpan          timeout,
        CancellationToken cancellationToken
    )
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            return await this.outbound.Reader.ReadAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }
}
