// ReSharper disable MethodSupportsCancellation // Using alternative method of cancelling tasks by throwing exceptions.

using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Dalamud.Bindings.ImGui;
using Dalamud.Game;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiFileDialog;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Logging.Internal;
using Dalamud.Utility;

using Serilog;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying task scheduler test.
/// </summary>
internal class TaskSchedulerWidget : IDataWindowWidget
{
    private readonly FileDialogManager fileDialogManager = new();
    private string url = "https://geo.mirror.pkgbuild.com/iso/2024.01.01/archlinux-2024.01.01-x86_64.iso";
    private string localPath = string.Empty;

    private Task? downloadTask = null;
    private (long Downloaded, long Total, float Percentage) downloadState;
    private CancellationTokenSource taskSchedulerCancelSource = new();

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["tasksched", "taskscheduler"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "任务调度器";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var framework = Service<Framework>.Get();

        if (ImGui.Button("清空列表"u8))
        {
            TaskTracker.Clear();
        }

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(10);
        ImGui.SameLine();

        if (ImGui.Button("通过 CancellationTokenSource 取消"u8))
        {
            this.taskSchedulerCancelSource.Cancel();
            this.taskSchedulerCancelSource = new();
        }

        ImGui.Text("在任意线程中运行："u8);
        ImGui.SameLine();

        if (ImGui.Button("短时 Task.Run"u8))
        {
            Task.Run(() => { Thread.Sleep(500); });
        }

        ImGui.SameLine();

        if (ImGui.Button("任务中的任务（Delay）"u8))
        {
            var token = this.taskSchedulerCancelSource.Token;
            Task.Run(async () => await this.TestTaskInTaskDelay(token), token);
        }

        ImGui.SameLine();

        if (ImGui.Button("任务中的任务（Sleep）"u8))
        {
            Task.Run(async () => await this.TestTaskInTaskSleep());
        }

        ImGui.SameLine();

        if (ImGui.Button("故障任务"u8))
        {
            Task.Run(() =>
            {
                Thread.Sleep(200);

                _ = ((string)null)!.Contains("dalamud"); // Intentional null exception.
            });
        }

        ImGui.Text("在 Framework.Update 中运行："u8);
        ImGui.SameLine();

        if (ImGui.Button("立即"u8))
        {
            _ = framework.RunOnTick(() => Log.Information("Framework.Update - 立即"), cancellationToken: this.taskSchedulerCancelSource.Token);
        }

        ImGui.SameLine();

        if (ImGui.Button("1 秒后"u8))
        {
            _ = framework.RunOnTick(() => Log.Information("Framework.Update - 1 秒后"), cancellationToken: this.taskSchedulerCancelSource.Token, delay: TimeSpan.FromSeconds(1));
        }

        ImGui.SameLine();

        if (ImGui.Button("60 帧后"u8))
        {
            _ = framework.RunOnTick(() => Log.Information("Framework.Update - 60 帧后"), cancellationToken: this.taskSchedulerCancelSource.Token, delayTicks: 60);
        }

        ImGui.SameLine();

        if (ImGui.Button("1 秒加 120 帧后"u8))
        {
            _ = framework.RunOnTick(() => Log.Information("Framework.Update - 1 秒加 120 帧后"), cancellationToken: this.taskSchedulerCancelSource.Token, delay: TimeSpan.FromSeconds(1), delayTicks: 120);
        }

        ImGui.SameLine();

        if (ImGui.Button("2 秒加 60 帧后"u8))
        {
            _ = framework.RunOnTick(() => Log.Information("Framework.Update - 2 秒加 60 帧后"), cancellationToken: this.taskSchedulerCancelSource.Token, delay: TimeSpan.FromSeconds(2), delayTicks: 60);
        }

        if (ImGui.Button("每 60 帧"u8))
        {
            _ = framework.RunOnTick(
                async () =>
                {
                    for (var i = 0L; ; i++)
                    {
                        Log.Information($"循环 #{i}；主线程={ThreadSafety.IsMainThread}");
                        var it = i;
                        _ = Task.Factory.StartNew(() => Log.Information($" => 子任务 #{it}；主线程={ThreadSafety.IsMainThread}"));
                        await framework.DelayTicks(60, this.taskSchedulerCancelSource.Token);
                    }
                },
                cancellationToken: this.taskSchedulerCancelSource.Token);
        }

        ImGui.SameLine();

        if (ImGui.Button("每 1 秒"u8))
        {
            _ = framework.RunOnTick(
                async () =>
                {
                    for (var i = 0L; ; i++)
                    {
                        Log.Information($"循环 #{i}；主线程={ThreadSafety.IsMainThread}");
                        var it = i;
                        _ = Task.Factory.StartNew(() => Log.Information($" => 子任务 #{it}；主线程={ThreadSafety.IsMainThread}"));
                        await Task.Delay(TimeSpan.FromSeconds(1), this.taskSchedulerCancelSource.Token);
                    }
                },
                cancellationToken: this.taskSchedulerCancelSource.Token);
        }

        ImGui.SameLine();

        if (ImGui.Button("每 60 帧（Await）"u8))
        {
            _ = framework.Run(
                async () =>
                {
                    for (var i = 0L; ; i++)
                    {
                        Log.Information($"循环 #{i}；主线程={ThreadSafety.IsMainThread}");
                        var it = i;
                        _ = Task.Factory.StartNew(() => Log.Information($" => 子任务 #{it}；主线程={ThreadSafety.IsMainThread}"));
                        await framework.DelayTicks(60, this.taskSchedulerCancelSource.Token);
                    }
                },
                this.taskSchedulerCancelSource.Token);
        }

        ImGui.SameLine();

        if (ImGui.Button("每 1 秒（Await）"u8))
        {
            _ = framework.Run(
                async () =>
                {
                    for (var i = 0L; ; i++)
                    {
                        Log.Information($"循环 #{i}；主线程={ThreadSafety.IsMainThread}");
                        var it = i;
                        _ = Task.Factory.StartNew(() => Log.Information($" => 子任务 #{it}；主线程={ThreadSafety.IsMainThread}"));
                        await Task.Delay(TimeSpan.FromSeconds(1), this.taskSchedulerCancelSource.Token);
                    }
                },
                this.taskSchedulerCancelSource.Token);
        }

        ImGui.SameLine();

        if (ImGui.Button("确保在框架线程中运行"u8))
        {
            Task.Run(async () => await framework.RunOnFrameworkThread(() => { Log.Information("从非 Framework.Update 线程派发任务"); }));
            framework.RunOnFrameworkThread(() => { Log.Information("从 Framework.Update 线程派发任务"); }).Wait();
        }

        ImGui.SameLine();

        if (ImGui.Button("1 秒后出错"u8))
        {
            _ = framework.RunOnTick(() => throw new Exception("测试异常"), cancellationToken: this.taskSchedulerCancelSource.Token, delay: TimeSpan.FromSeconds(1));
        }

        ImGui.SameLine();

        if (ImGui.Button("冻结 1 秒"u8))
        {
            _ = framework.RunOnFrameworkThread(() => Helper().Wait());
            static async Task Helper() => await Task.Delay(1000);
        }

        ImGui.SameLine();

        if (ImGui.Button("完全冻结"u8))
        {
            _ = framework.Run(() => Helper().Wait());
            static async Task Helper() => await Task.Delay(1000);
        }

        if (ImGui.CollapsingHeader("下载"u8))
        {
            ImGui.InputText("URL"u8, ref this.url);
            ImGui.InputText("本地路径"u8, ref this.localPath);
            ImGui.SameLine();

            if (ImGuiComponents.IconButton("##localpathpicker", FontAwesomeIcon.File))
            {
                var defaultFileName = this.url.Split('\0', 2)[0].Split('/').Last();
                this.fileDialogManager.SaveFileDialog(
                    "选择本地路径",
                    "*",
                    defaultFileName,
                    string.Empty,
                    (accept, newPath) =>
                    {
                        if (accept)
                        {
                            this.localPath = newPath;
                        }
                    });
            }

            ImGui.Text($"{this.downloadState.Downloaded:##,###}/{this.downloadState.Total:##,###} ({this.downloadState.Percentage:0.00}%)");

            using var disabled = ImRaii.Disabled(this.downloadTask?.IsCompleted is false || string.IsNullOrEmpty(this.localPath));
            ImGui.AlignTextToFramePadding();
            ImGui.Text("下载方式"u8);
            ImGui.SameLine();
            var downloadUsingGlobalScheduler = ImGui.Button("使用默认调度器"u8);
            ImGui.SameLine();
            var downloadUsingFramework = ImGui.Button("使用 Framework.Update"u8);
            if (downloadUsingGlobalScheduler || downloadUsingFramework)
            {
                var ct = this.taskSchedulerCancelSource.Token;
                this.downloadState = default;
                var factory = downloadUsingGlobalScheduler
                                  ? Task.Factory
                                  : framework.GetTaskFactory();
                this.downloadState = default;
                this.downloadTask = factory.StartNew(
                    async () =>
                    {
                        try
                        {
                            await using var to = File.Create(this.localPath);
                            using var client = new HttpClient();
                            using var conn = await client.GetAsync(this.url, HttpCompletionOption.ResponseHeadersRead, ct);
                            this.downloadState.Total = conn.Content.Headers.ContentLength ?? -1L;
                            await using var from = conn.Content.ReadAsStream(ct);
                            var buffer = new byte[8192];
                            while (true)
                            {
                                if (downloadUsingFramework)
                                    ThreadSafety.AssertMainThread();
                                if (downloadUsingGlobalScheduler)
                                    ThreadSafety.AssertNotMainThread();
                                var len = await from.ReadAsync(buffer, ct);
                                if (len == 0)
                                    break;
                                await to.WriteAsync(buffer.AsMemory(0, len), ct);
                                this.downloadState.Downloaded += len;
                                if (this.downloadState.Total >= 0)
                                {
                                    this.downloadState.Percentage =
                                        (100f * this.downloadState.Downloaded) / this.downloadState.Total;
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Log.Error(e, "无法将 {from} 下载到 {to}。", this.url, this.localPath);
                            try
                            {
                                File.Delete(this.localPath);
                            }
                            catch
                            {
                                // ignore
                            }
                        }
                    },
                    cancellationToken: ct).Unwrap();
            }
        }

        if (ImGui.Button("创建海量任务"u8))
        {
            var token = this.taskSchedulerCancelSource.Token;
            Task.Run(
                () =>
                {
                    for (var i = 0; i < 100; i++)
                    {
                        token.ThrowIfCancellationRequested();
                        Task.Run(
                            () =>
                            {
                                for (var j = 0; j < 100; j++)
                                {
                                    token.ThrowIfCancellationRequested();
                                    Task.Run(
                                        () =>
                                        {
                                            for (var k = 0; k < 100; k++)
                                            {
                                                token.ThrowIfCancellationRequested();
                                                Task.Run(
                                                    () =>
                                                    {
                                                        for (var l = 0; l < 100; l++)
                                                        {
                                                            token.ThrowIfCancellationRequested();
                                                            Task.Run(
                                                                async () =>
                                                                {
                                                                    for (var m = 0; m < 100; m++)
                                                                    {
                                                                        token.ThrowIfCancellationRequested();
                                                                        await Task.Delay(1, token);
                                                                    }
                                                                });
                                                        }
                                                    });
                                            }
                                        });
                                }
                            });
                    }
                });
        }

        ImGui.SameLine();

        ImGuiHelpers.ScaledDummy(20);

        // Needed to init the task tracker, if we're not on a debug build
        Service<TaskTracker>.Get().Enable();

        for (var i = 0; i < TaskTracker.Tasks.Count; i++)
        {
            var task = TaskTracker.Tasks[i];
            var subTime = DateTime.Now;
            if (task.Task == null)
                subTime = task.FinishTime;

            using var pushedColor = task.Status switch
            {
                TaskStatus.Created or TaskStatus.WaitingForActivation or TaskStatus.WaitingToRun
                    => ImRaii.PushColor(ImGuiCol.Header, ImGuiColors.DalamudGrey),
                TaskStatus.Running or TaskStatus.WaitingForChildrenToComplete
                    => ImRaii.PushColor(ImGuiCol.Header, ImGuiColors.InfoForeground),
                TaskStatus.RanToCompletion
                    => ImRaii.PushColor(ImGuiCol.Header, ImGuiColors.SuccessForeground),
                TaskStatus.Canceled or TaskStatus.Faulted
                    => ImRaii.PushColor(ImGuiCol.Header, ImGuiColors.ErrorForeground),

                _ => throw new ArgumentOutOfRangeException(),
            };

            if (ImGui.CollapsingHeader($"#{task.Id} - {task.Status} {(subTime - task.StartTime).TotalMilliseconds} ms###task{i}"))
            {
                task.IsBeingViewed = true;

                if (ImGui.Button("取消（可能无效）"u8))
                {
                    try
                    {
                        var cancelFunc = typeof(Task).GetMethod("InternalCancel", BindingFlags.NonPublic | BindingFlags.Instance);
                        cancelFunc?.Invoke(task, null);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "无法取消任务");
                    }
                }

                ImGuiHelpers.ScaledDummy(10);

                ImGui.Text(task.StackTrace?.ToString() ?? "堆栈跟踪为空");

                if (task.Exception != null)
                {
                    ImGuiHelpers.ScaledDummy(15);
                    ImGui.TextColored(ImGuiColors.ErrorForeground, "异常："u8);
                    ImGui.Text(task.Exception.ToString());
                }
            }
            else
            {
                task.IsBeingViewed = false;
            }
        }

        this.fileDialogManager.Draw();
    }

    private async Task TestTaskInTaskDelay(CancellationToken token)
    {
        await Task.Delay(5000, token);
    }

#pragma warning disable 1998
    private async Task TestTaskInTaskSleep()
#pragma warning restore 1998
    {
        Thread.Sleep(5000);
    }
}
