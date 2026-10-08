using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Dalamud;

/// <summary>
/// 无状态流式 HTTP 端点。每个 POST 请求建立一个独立的 MCP 服务器实例。
/// </summary>
internal sealed class MCPHttpServer : IDisposable
{
    private const           string   SERVER_VERSION  = "1.0.0";
    private static readonly TimeSpan REQUEST_TIMEOUT = TimeSpan.FromSeconds(20);

    private readonly HttpListener                                listener = new();
    private readonly McpServerPrimitiveCollection<McpServerTool> tools;
    private readonly CancellationTokenSource                     cancellation = new();
    private          Implementation?                             knownClientInfo;
    private          ClientCapabilities?                         knownClientCapabilities;
    private          bool                                        disposed;

    /// <summary>
    /// 初始化 <see cref="MCPHttpServer"/> 类的新实例。
    /// </summary>
    /// <param name="port">监听端口。</param>
    /// <param name="tools">对外暴露的工具集合。</param>
    public MCPHttpServer
    (
        int                                         port,
        McpServerPrimitiveCollection<McpServerTool> tools
    )
    {
        this.tools = tools;
        this.listener.Prefixes.Add($"http://127.0.0.1:{port}/mcp/");
    }

    /// <summary>
    /// 开始监听。
    /// </summary>
    public void Start()
    {
        this.listener.Start();
        _ = this.AcceptLoopAsync();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (this.disposed)
            return;

        this.disposed = true;
        this.cancellation.Cancel();

        try
        {
            this.listener.Stop();
            this.listener.Close();
        }
        catch (Exception)
        {
            // ignored
        }

        this.cancellation.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (!this.cancellation.IsCancellationRequested)
        {
            HttpListenerContext context;

            try
            {
                context = await this.listener.GetContextAsync();
            }
            catch (Exception) when (this.cancellation.IsCancellationRequested)
            {
                break;
            }
            catch (HttpListenerException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            _ = Task.Run(() => this.HandleAsync(context), CancellationToken.None);
        }
    }

    private async Task HandleAsync
    (
        HttpListenerContext context
    )
    {
        var response = context.Response;

        try
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.Ordinal))
            {
                response.StatusCode = 405;
                return;
            }

            string body;
            using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                body = await reader.ReadToEndAsync(this.cancellation.Token);

            var message = JsonSerializer.Deserialize<JsonRpcMessage>(body, McpJsonUtilities.DefaultOptions);

            if (message is null)
            {
                response.StatusCode = 400;
                return;
            }

            await using var transport = new StatelessTransport();

            var options = new McpServerOptions
            {
                ServerInfo = new Implementation
                {
                    Name    = "dalamud-mcp",
                    Version = SERVER_VERSION
                },
                Capabilities = new ServerCapabilities
                {
                    Tools = new ToolsCapability()
                },
                ToolCollection          = this.tools,
                ScopeRequests           = false,
                KnownClientInfo         = Volatile.Read(ref this.knownClientInfo),
                KnownClientCapabilities = Volatile.Read(ref this.knownClientCapabilities)
            };

            await using var server = McpServer.Create(transport, options);
            _ = server.RunAsync(this.cancellation.Token);

            await transport.DeliverAsync(message, this.cancellation.Token);

            if (message is JsonRpcNotification)
            {
                response.StatusCode = 202;
                return;
            }

            var reply = await transport.ReadOutboundAsync(REQUEST_TIMEOUT, this.cancellation.Token);

            if (reply is null)
            {
                response.StatusCode = 504;
                return;
            }

            if (this.knownClientInfo is null && server.ClientInfo is not null)
            {
                this.knownClientInfo         = server.ClientInfo;
                this.knownClientCapabilities = server.ClientCapabilities;
            }

            var json  = JsonSerializer.Serialize(reply, McpJsonUtilities.DefaultOptions);
            var bytes = Encoding.UTF8.GetBytes(json);

            response.ContentType     = "application/json; charset=utf-8";
            response.StatusCode      = 200;
            response.ContentLength64 = bytes.Length;
            await response.OutputStream.WriteAsync(bytes, this.cancellation.Token);
        }
        catch (Exception exception)
        {
            MCPRuntime.Trace.Write("http_error", exception.ToString());

            try
            {
                response.StatusCode = 500;
            }
            catch (Exception)
            {
                // ignored
            }
        }
        finally
        {
            try
            {
                response.Close();
            }
            catch (Exception)
            {
                // ignored
            }
        }
    }
}
