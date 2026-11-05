using System.Threading;
using System.Threading.Tasks;
using Dalamud.Game;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>串行播放完整输入事务；不会激活窗口或移动桌面光标。</summary>
internal static class InputSender
{
    private static readonly SemaphoreSlim  Gate = new(1, 1);
    private static          InputPlayback? playback;

    public static bool IsPluginPlaybackActive => Volatile.Read(ref playback)?.Plugin == true;

    public static bool ApplyImGuiFrame() => Volatile.Read(ref playback)?.ApplyImGui() == true;

    public static async Task<int> Send(InputAction[] actions, bool plugin, string? screenshot, CancellationToken cancellationToken)
    {
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var (width, height) = WindowInfo.GetRenderSize();
            if (width <= 0 || height <= 0)
                throw new McpException("渲染窗口尚未就绪。");

            var reference = screenshot is null ?
                                null :
                                CaptureStore.Get(screenshot);
            if (reference is not null && (reference.SourceWidth != width || reference.SourceHeight != height))
                throw new McpException("参考截图之后渲染尺寸已改变，请重新截图。");

            var       plan      = InputPlan.Create(actions, reference, plugin, width, height);
            var       framework = Service<Framework>.Get();
            using var deadline  = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            var current = await framework.Run
                          (
                              () =>
                              {
                                  token.ThrowIfCancellationRequested();
                                  var session = new InputPlayback(plan, plugin);
                                  session.Install();
                                  Volatile.Write(ref playback, session);
                                  return session;
                              },
                              token
                          ).ConfigureAwait(false);

            try
            {
                await current.Completion.WaitAsync(token).ConfigureAwait(false);
                return plan.Count;
            }
            finally
            {
                Interlocked.CompareExchange(ref playback, null, current);
                current.Dispose();
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    public static void Stop() => Interlocked.Exchange(ref playback, null)?.Dispose();
}
