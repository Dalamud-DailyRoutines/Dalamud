using Dalamud.Configuration.Internal;
using ModelContextProtocol.Server;
using Serilog;

namespace Dalamud;

/// <summary>
/// 调试用 MCP 服务器宿主。仅在开发者模式开启时监听。
/// </summary>
[ServiceManager.EarlyLoadedService]
internal sealed class MCPHost : IInternalDisposableService
{
    private MCPHttpServer? server;

    /// <summary>
    /// 初始化 <see cref="MCPHost"/> 类的新实例。
    /// </summary>
    /// <param name="configuration">Dalamud 配置。</param>
    [ServiceManager.ServiceConstructor]
    private MCPHost
    (
        DalamudConfiguration configuration
    )
    {
        if (configuration.DevMode != true)
            return;

        this.Start(configuration.MCPPort);
    }

    /// <inheritdoc/>
    void IInternalDisposableService.DisposeService()
    {
        if (this.server is null)
            return;

        this.server.Dispose();
        this.server = null;

        MCPRuntime.Shutdown();
        MCPRuntime.IsRunning = false;
        MCPRuntime.Trace.Write("host", "已停止监听");
    }

    /// <summary>
    /// 在失败后重新尝试启动。
    /// </summary>
    internal void RetryStart()
    {
        if (this.server is not null)
            return;

        this.Start(Service<DalamudConfiguration>.Get().MCPPort);
    }

    private void Start
    (
        int port
    )
    {
        McpServerPrimitiveCollection<McpServerTool> tools;

        try
        {
            tools = ToolCatalog.Create();
        }
        catch (Exception exception)
        {
            ReportFailure("创建工具目录失败", exception);
            return;
        }

        try
        {
            this.server = new MCPHttpServer(port, tools);
        }
        catch (Exception exception)
        {
            this.server = null;
            ReportFailure("创建监听端点失败", exception);
            return;
        }

        try
        {
            this.server.Start();
        }
        catch (Exception exception)
        {
            this.server.Dispose();
            this.server = null;
            ReportFailure("启动监听失败", exception);
            return;
        }

        MCPRuntime.Port      = port;
        MCPRuntime.IsRunning = true;
        MCPRuntime.LastError = null;
        MCPRuntime.Trace.Write("host", $"监听 http://127.0.0.1:{port}/mcp/");
        Log.Information("MCP 调试服务器已监听 http://127.0.0.1:{Port}/mcp/", port);
    }

    private static void ReportFailure
    (
        string    stage,
        Exception exception
    )
    {
        MCPRuntime.IsRunning = false;
        MCPRuntime.LastError = $"{stage}: {exception.GetType().Name}: {exception.Message}";
        MCPRuntime.Trace.Write("host_error", $"{stage}: {exception}");
        Log.Error(exception, "MCP 调试服务器{Stage}", stage);
    }
}
