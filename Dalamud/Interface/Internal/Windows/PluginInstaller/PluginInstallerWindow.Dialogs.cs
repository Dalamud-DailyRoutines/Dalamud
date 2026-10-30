using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Colors;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;
using Dalamud.Support;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private bool errorModalDrawing = true;

    private bool errorModalOnNextFrame;

    private string errorModalMessage = string.Empty;

    private TaskCompletionSource? errorModalTaskCompletionSource;

    private bool updateModalDrawing = true;

    private bool updateModalOnNextFrame;

    private LocalPlugin? updateModalPlugin;

    private TaskCompletionSource<bool>? updateModalTaskCompletionSource;

    private bool testingWarningModalDrawing = true;

    private bool testingWarningModalOnNextFrame;

    private bool deletePluginConfigWarningModalDrawing = true;

    private bool deletePluginConfigWarningModalOnNextFrame;

    private bool deletePluginConfigWarningModalExplainTesting;

    private string deletePluginConfigWarningModalPluginName = string.Empty;

    private TaskCompletionSource<bool>? deletePluginConfigWarningModalTaskCompletionSource;

    private bool feedbackModalDrawing = true;

    private bool feedbackModalOnNextFrame;

    private bool feedbackModalOnNextFrameDontClear;

    private string feedbackModalBody = string.Empty;

    private string feedbackModalContact = string.Empty;

    private bool feedbackModalIncludeException;

    private RemotePluginManifest? feedbackPlugin;

    private bool feedbackIsTesting;

    private void DrawErrorModal()
    {
        const string MODAL_TITLE = "安装器错误";

        if (ImGui.BeginPopupModal(MODAL_TITLE, ref this.errorModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text(this.errorModalMessage);
            ImGui.Spacing();

            const float BUTTON_WIDTH = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ((BUTTON_WIDTH * 2) - (ImGui.GetStyle().ItemSpacing.Y * 2))) / 2);

            if (ImGui.Button("确定", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.errorModalTaskCompletionSource?.TrySetResult();
            }

            ImGui.SameLine();

            if (ImGui.Button("查看日志", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.errorModalTaskCompletionSource?.TrySetResult();
                Service<DalamudInterface>.Get().OpenLogWindow();
            }

            ImGui.EndPopup();
        }

        if (!this.errorModalDrawing)
            this.errorModalTaskCompletionSource?.TrySetResult();

        if (this.errorModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(MODAL_TITLE);
            this.errorModalOnNextFrame = false;
            this.errorModalDrawing     = true;
        }
    }

    private void DrawUpdateModal()
    {
        const string MODAL_TITLE = "可用更新";

        if (this.updateModalPlugin == null)
            return;

        if (ImGui.BeginPopupModal(MODAL_TITLE, ref this.updateModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text($"插件“{this.updateModalPlugin.Name}”有可用更新\n是否在启用前更新？\n更新将修复错误和不兼容问题，并可能添加新功能");
            ImGui.Spacing();

            const float BUTTON_WIDTH = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ((BUTTON_WIDTH * 2) - (ImGui.GetStyle().ItemSpacing.Y * 2))) / 2);

            using (ImRaii.Disabled(!Service<PluginManager>.Get().ReposReady || this.availablePluginsChanged != 0))
            {
                if (ImGui.Button("更新插件", new Vector2(BUTTON_WIDTH, 40)))
                {
                    ImGui.CloseCurrentPopup();
                    this.updateModalTaskCompletionSource?.TrySetResult(true);
                }
            }

            ImGui.SameLine();

            if (ImGui.Button("仅启用", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.updateModalTaskCompletionSource?.TrySetResult(false);
            }

            ImGui.EndPopup();
        }

        if (!this.updateModalDrawing)
            this.updateModalTaskCompletionSource?.TrySetCanceled();

        if (this.updateModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(MODAL_TITLE);
            this.updateModalOnNextFrame = false;
            this.updateModalDrawing     = true;
        }
    }

    private void DrawTestingWarningModal()
    {
        const string MODAL_TITLE = "警告###InstallerTestingWarning";

        if (ImGui.BeginPopupModal(MODAL_TITLE, ref this.testingWarningModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text("注意：退出插件测试版后，将继续使用测试版，直到删除并重新安装插件，或者插件的非测试版本更新\n手动降级可能会丢失此插件的设置");

            ImGuiHelpers.ScaledDummy(10);

            const float BUTTON_WIDTH = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - BUTTON_WIDTH) / 2);

            if (ImGui.Button("确定", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
            }

            ImGui.EndPopup();
        }

        if (this.testingWarningModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(MODAL_TITLE);
            this.testingWarningModalOnNextFrame = false;
            this.testingWarningModalDrawing     = true;
        }
    }

    private Task<bool> ShowDeletePluginConfigWarningModal
    (
        string pluginName,
        bool   explainTesting = false
    )
    {
        if (this.disposed)
            return Task.FromResult(false);

        this.deletePluginConfigWarningModalDrawing        = true;
        this.deletePluginConfigWarningModalOnNextFrame    = true;
        this.deletePluginConfigWarningModalPluginName     = pluginName;
        this.deletePluginConfigWarningModalExplainTesting = explainTesting;
        this.deletePluginConfigWarningModalTaskCompletionSource?.TrySetResult(false);
        this.deletePluginConfigWarningModalTaskCompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        return this.deletePluginConfigWarningModalTaskCompletionSource.Task;
    }

    private void DrawDeletePluginConfigWarningModal()
    {
        const string MODAL_TITLE = "警告###InstallerDeletePluginConfigWarning";

        if (ImGui.BeginPopupModal(MODAL_TITLE, ref this.deletePluginConfigWarningModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            if (this.deletePluginConfigWarningModalExplainTesting)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.WarningForeground);
                ImGui.Text("如仅想禁用测试版，请勿选择此选项");
                ImGui.PopStyleColor();
            }

            ImGui.Text($"确定要删除 {this.deletePluginConfigWarningModalPluginName} 的所有数据和配置吗？\n将丢失此插件的所有设置");
            ImGui.Spacing();

            const float BUTTON_WIDTH = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ((BUTTON_WIDTH * 2) - (ImGui.GetStyle().ItemSpacing.Y * 2))) / 2);

            if (ImGui.Button("是", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.deletePluginConfigWarningModalTaskCompletionSource?.TrySetResult(true);
            }

            ImGui.SameLine();

            if (ImGui.Button("否", new Vector2(BUTTON_WIDTH, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.deletePluginConfigWarningModalTaskCompletionSource?.TrySetResult(false);
            }

            ImGui.EndPopup();
        }

        if (!this.deletePluginConfigWarningModalDrawing)
            this.deletePluginConfigWarningModalTaskCompletionSource?.TrySetResult(false);

        if (this.deletePluginConfigWarningModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(MODAL_TITLE);
            this.deletePluginConfigWarningModalOnNextFrame = false;
            this.deletePluginConfigWarningModalDrawing     = true;
        }
    }

    private void DrawFeedbackModal()
    {
        const string MODAL_TITLE = "发送反馈";

        if (this.feedbackPlugin == null)
            return;

        if (ImGui.BeginPopupModal(MODAL_TITLE, ref this.feedbackModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text($"可在此处向插件“{this.feedbackPlugin?.Name}”的开发者发送反馈。");

            if (this.feedbackPlugin?.FeedbackMessage != null)
            {
                ImGui.TextWrapped(this.feedbackPlugin.FeedbackMessage);
            }

            if (this.pluginListUpdatable.Any(up => up.InstalledPlugin.Manifest.InternalName == this.feedbackPlugin?.InternalName))
            {
                ImGui.TextColored(ImGuiColors.AttentionForeground, "此插件有新版本可用，请在报告问题前先更新");
            }

            ImGui.Spacing();

            ImGui.InputTextMultiline("###FeedbackContent"u8, ref this.feedbackModalBody, 1000, new Vector2(400, 200));

            ImGui.Spacing();

            ImGui.InputText("联系信息", ref this.feedbackModalContact, 100);

            ImGui.SameLine();

            if (ImGui.Button("加入 XIVLauncher 与 Dalamud 的 Discord 服务器"))
            {
                Process.Start
                (
                    new ProcessStartInfo("https://goat.place/")
                    {
                        UseShellExecute = true
                    }
                );
            }

            ImGui.Text("接受 Discord 用户名和电子邮件地址\n如提交 Discord 用户名，请加入 Discord 服务器，以便更容易联系");

            ImGui.TextColored(ImGuiColors.WarningForeground, "请勿提交游戏内角色名称");

            ImGui.Spacing();

            ImGui.BeginDisabled();
            ImGui.Checkbox("包含最后的错误信息", ref this.feedbackModalIncludeException);
            ImGui.EndDisabled();

            ImGui.TextColored(ImGuiColors.DalamudGrey, "此选项可以为插件开发者提供关于具体问题的有用反馈");

            ImGui.Spacing();

            ImGui.TextColored(ImGuiColors.DalamudGrey, "所有插件开发者都将能够看到反馈内容\n请勿包含任何个人或敏感信息\n如选择包含最后的错误信息，可能会包含诸如 Windows 用户名等信息\n\n收集的反馈不会存储在服务端，而是直接转发到 Discord");

            const float BUTTON_WIDTH = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - BUTTON_WIDTH) / 2);

            if (ImGui.Button("确定", new Vector2(BUTTON_WIDTH, 40)))
            {
                if (string.IsNullOrWhiteSpace(this.feedbackModalContact))
                {
                    this.ShowErrorModal("未提供联系信息，需要联系信息来回复问题，或请求额外信息以解决问题")
                        .ContinueWith
                        (_ =>
                            {
                                this.feedbackModalOnNextFrameDontClear = true;
                                this.feedbackModalOnNextFrame          = true;
                            }
                        );
                }
                else
                {
                    if (this.feedbackPlugin != null)
                    {
                        Task.Run
                            (async () => await BugBait.SendFeedback
                                         (
                                             this.feedbackPlugin,
                                             this.feedbackIsTesting,
                                             this.feedbackModalBody,
                                             this.feedbackModalContact,
                                             this.feedbackModalIncludeException
                                         )
                            )
                            .ContinueWith
                            (t =>
                                {
                                    var notif = Service<NotificationManager>.Get();

                                    if (t.IsCanceled || t.IsFaulted)
                                    {
                                        notif.AddNotification
                                        (
                                            "无法发送反馈",
                                            "发送反馈",
                                            NotificationType.Error
                                        );
                                    }
                                    else
                                    {
                                        notif.AddNotification
                                        (
                                            "反馈已成功发送",
                                            "发送反馈",
                                            NotificationType.Success
                                        );
                                    }
                                }
                            );
                    }
                    else
                    {
                        Log.Error("FeedbackPlugin was null");
                    }

                    if (!string.IsNullOrWhiteSpace(this.feedbackModalContact))
                    {
                        Service<DalamudConfiguration>.Get().LastFeedbackContactDetails = this.feedbackModalContact;
                    }

                    ImGui.CloseCurrentPopup();
                }
            }

            ImGui.EndPopup();
        }

        if (this.feedbackModalOnNextFrame)
        {
            ImGui.OpenPopup(MODAL_TITLE);
            this.feedbackModalOnNextFrame = false;
            this.feedbackModalDrawing     = true;

            if (!this.feedbackModalOnNextFrameDontClear)
            {
                this.feedbackModalBody             = string.Empty;
                this.feedbackModalContact          = Service<DalamudConfiguration>.Get().LastFeedbackContactDetails;
                this.feedbackModalIncludeException = true;
            }
            else
            {
                this.feedbackModalOnNextFrameDontClear = false;
            }
        }
    }

    private Task ShowErrorModal
    (
        string message
    )
    {
        using var scope = this.listLock.EnterScope();
        if (this.disposed)
            return Task.CompletedTask;

        if (this.errorModalTaskCompletionSource is { Task.IsCompleted: false })
        {
            this.errorModalMessage += $"\n\n{message}";
            return this.errorModalTaskCompletionSource.Task;
        }

        this.errorModalMessage              = message;
        this.errorModalDrawing              = true;
        this.errorModalOnNextFrame          = true;
        this.errorModalTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return this.errorModalTaskCompletionSource.Task;
    }

    private Task<bool> ShowUpdateModal
    (
        LocalPlugin plugin
    )
    {
        if (this.disposed)
            return Task.FromCanceled<bool>(new CancellationToken(true));

        this.updateModalTaskCompletionSource?.TrySetCanceled();
        this.updateModalDrawing              = true;
        this.updateModalOnNextFrame          = true;
        this.updateModalPlugin               = plugin;
        this.updateModalTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return this.updateModalTaskCompletionSource.Task;
    }
}
