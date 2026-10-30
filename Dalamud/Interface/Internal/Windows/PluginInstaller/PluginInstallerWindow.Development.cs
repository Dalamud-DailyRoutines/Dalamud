using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.Textures.Internal;
using Dalamud.Interface.Textures.TextureWraps;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Profiles;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private readonly string[] testerImagePaths = new string[5];

    private string testerIconPath = string.Empty;

    private Task<IDalamudTextureWrap>?[]? testerImages;

    private Task<IDalamudTextureWrap>? testerIcon;

    private bool testerError;

    private bool testerUpdateAvailable;

    private void DrawImageTester()
    {
        var sectionSize = ImGuiHelpers.GlobalScale * 66;
        var startCursor = ImGui.GetCursorPos();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.5f, 0.5f, 0.1f));

        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.5f, 0.5f, 0.5f, 0.2f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  new Vector4(0.5f, 0.5f, 0.5f, 0.35f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 0);

        ImGui.Button($"###pluginTesterCollapsibleBtn", new Vector2(ImGui.GetWindowWidth() - (ImGuiHelpers.GlobalScale * 35), sectionSize));

        ImGui.PopStyleVar();

        ImGui.PopStyleColor(3);

        ImGui.SetCursorPos(startCursor);

        var hasIcon = this.testerIcon?.IsCompletedSuccessfully is true;

        var iconTex          = this.imageCache.DefaultIcon;
        if (hasIcon) iconTex = this.testerIcon.Result;

        var iconSize = ImGuiHelpers.ScaledVector2(64, 64);

        var cursorBeforeImage = ImGui.GetCursorPos();
        ImGui.Image(iconTex.Handle, iconSize);
        ImGui.SameLine();

        if (this.testerError)
        {
            ImGui.SetCursorPos(cursorBeforeImage);
            ImGui.Image(this.imageCache.TroubleIcon.Handle, iconSize);
            ImGui.SameLine();
        }
        else if (this.testerUpdateAvailable)
        {
            ImGui.SetCursorPos(cursorBeforeImage);
            ImGui.Image(this.imageCache.UpdateIcon.Handle, iconSize);
            ImGui.SameLine();
        }

        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        var cursor = ImGui.GetCursorPos();
        // Name
        ImGui.Text("示例插件"u8);

        // Download count
        var downloadCountText = $"作者：示例作者（{69420:N0} 次下载）";

        ImGui.SameLine();
        ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadCountText);

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        // Description
        ImGui.TextWrapped("这里显示插件简介。"u8);

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);

        ImGuiHelpers.ScaledDummy(5);

        ImGui.Indent();

        // Description
        ImGui.TextWrapped("这里显示插件说明。\n支持多行文字。\n用于预览插件信息的显示效果。"u8);

        ImGuiHelpers.ScaledDummy(5);

        // Controls
        var disabled = this.updateStatus == OperationStatus.InProgress || this.installStatus == OperationStatus.InProgress;

        const string VERSION_STRING = "1.0.0.0";

        if (disabled)
        {
            ImGuiComponents.DisabledButton($"安装 v{VERSION_STRING}");
        }
        else
        {
            const string BUTTON_TEXT = $"安装 v{VERSION_STRING}";
            ImGui.Button($"{BUTTON_TEXT}##{BUTTON_TEXT}testing");
        }

        this.DrawVisitRepoUrlButton("https://google.com", true);

        if (this.testerImages != null)
        {
            ImGuiHelpers.ScaledDummy(5);

            const float THUMB_FACTOR = 2.7f;

            const int SCROLL_BAR_SIZE = 15;
            ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, SCROLL_BAR_SIZE);
            ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, Vector4.Zero);

            var width = ImGui.GetWindowWidth();

            if (ImGui.BeginChild
                (
                    "pluginTestingImageScrolling"u8,
                    new Vector2(width - (70 * ImGuiHelpers.GlobalScale), (PluginImageCache.PluginImageHeight / THUMB_FACTOR) + SCROLL_BAR_SIZE),
                    false,
                    ImGuiWindowFlags.HorizontalScrollbar |
                    ImGuiWindowFlags.NoScrollWithMouse   |
                    ImGuiWindowFlags.NoBackground
                ))
            {
                if (this.testerImages is { Length: > 0 })
                {
                    for (var i = 0; i < this.testerImages.Length; i++)
                    {
                        var popupId   = $"pluginTestingImage{i}";
                        var imageTask = this.testerImages[i];
                        if (imageTask == null)
                            continue;

                        if (!imageTask.IsCompleted)
                        {
                            ImGui.Text("加载中……"u8);
                            continue;
                        }

                        if (imageTask.Exception is not null)
                        {
                            ImGui.Text(imageTask.Exception.ToString());
                            continue;
                        }

                        var image = imageTask.Result;

                        ImGui.PushStyleVar(ImGuiStyleVar.PopupBorderSize, 0);
                        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding,   Vector2.Zero);
                        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,    Vector2.Zero);

                        if (ImGui.BeginPopup(popupId))
                        {
                            if (ImGui.ImageButton(image.Handle, new Vector2(image.Width, image.Height)))
                                ImGui.CloseCurrentPopup();

                            ImGui.EndPopup();
                        }

                        ImGui.PopStyleVar(3);

                        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                        float       xAct  = image.Width;
                        float       yAct  = image.Height;
                        const float X_MAX = PluginImageCache.PluginImageWidth;
                        const float Y_MAX = PluginImageCache.PluginImageHeight;

                        // scale image if undersized
                        if (xAct < X_MAX && yAct < Y_MAX)
                        {
                            var scale = Math.Min(X_MAX / xAct, Y_MAX / yAct);
                            xAct *= scale;
                            yAct *= scale;
                        }

                        var size = ImGuiHelpers.ScaledVector2(xAct / THUMB_FACTOR, yAct / THUMB_FACTOR);
                        if (ImGui.ImageButton(image.Handle, size))
                            ImGui.OpenPopup(popupId);

                        ImGui.PopStyleVar();

                        if (i < this.testerImages.Length - 1)
                        {
                            ImGui.SameLine();
                            ImGuiHelpers.ScaledDummy(5);
                            ImGui.SameLine();
                        }
                    }
                }
            }

            ImGui.EndChild();

            ImGui.PopStyleVar();
            ImGui.PopStyleColor();

            ImGui.Unindent();
        }

        ImGuiHelpers.ScaledDummy(20);

        ImGui.InputText("图标路径"u8, ref this.testerIconPath, 1000);
        if (this.testerIcon != null)
            CheckImageSize(this.testerIcon, PluginImageCache.PluginIconWidth, PluginImageCache.PluginIconHeight, true);
        ImGui.InputText("图片 1 路径"u8, ref this.testerImagePaths[0], 1000);
        if (this.testerImages?.Length > 0)
            CheckImageSize(this.testerImages[0], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("图片 2 路径"u8, ref this.testerImagePaths[1], 1000);
        if (this.testerImages?.Length > 1)
            CheckImageSize(this.testerImages[1], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("图片 3 路径"u8, ref this.testerImagePaths[2], 1000);
        if (this.testerImages?.Length > 2)
            CheckImageSize(this.testerImages[2], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("图片 4 路径"u8, ref this.testerImagePaths[3], 1000);
        if (this.testerImages?.Length > 3)
            CheckImageSize(this.testerImages[3], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("图片 5 路径"u8, ref this.testerImagePaths[4], 1000);
        if (this.testerImages?.Length > 4)
            CheckImageSize(this.testerImages[4], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);

        var tm = Service<TextureManager>.Get();

        if (ImGui.Button("加载"u8))
        {
            try
            {
                _               = this.testerIcon?.ToContentDisposedTask();
                this.testerIcon = null;

                if (this.testerImages != null)
                {
                    foreach (var image in this.testerImages)
                        _ = image?.ToContentDisposedTask();
                }

                if (!this.testerIconPath.IsNullOrEmpty())
                {
                    this.testerIcon = tm.Shared.GetFromFile(this.testerIconPath).RentAsync();
                }

                this.testerImages = new Task<IDalamudTextureWrap>?[this.testerImagePaths.Length];

                for (var i = 0; i < this.testerImagePaths.Length; i++)
                {
                    if (this.testerImagePaths[i].IsNullOrEmpty())
                        continue;

                    this.testerImages[i] = tm.Shared.GetFromFile(this.testerImagePaths[i]).RentAsync();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Could not load plugin images for testing");
            }
        }

        ImGui.Checkbox("显示错误标记"u8, ref this.testerError);
        ImGui.Checkbox("显示更新标记"u8, ref this.testerUpdateAvailable);

        return;

        static void CheckImageSize
        (
            Task<IDalamudTextureWrap>? imageTask,
            int                        maxWidth,
            int                        maxHeight,
            bool                       requireSquare
        )
        {
            if (imageTask == null)
                return;

            if (!imageTask.IsCompleted)
            {
                ImGui.Text("正在加载……"u8);
                return;
            }

            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            if (imageTask.Exception is { } exc)
            {
                ImGui.Text(exc.ToString());
            }
            else if (imageTask.IsCompletedSuccessfully)
            {
                var image = imageTask.Result;

                if (image.Width > maxWidth || image.Height > maxHeight)
                {
                    ImGui.Text
                    (
                        $"图片分辨率超出限制（{image.Width} × {image.Height}，最大为 {maxWidth} × {maxHeight}）"
                    );
                }

                if (requireSquare && image.Width != image.Height)
                    ImGui.Text($"图标必须为正方形，当前尺寸为 {image.Width} × {image.Height}。");
            }

            ImGui.PopStyleColor();
        }

    }

    private static void DrawDevPluginValidationIssues
    (
        LocalDevPlugin devPlugin
    )
    {
        if (!devPlugin.IsLoaded)
        {
            ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "加载后可显示开发警告。"u8);
        }
        else
        {
            var problems = PluginValidator.CheckForProblems(devPlugin);

            if (problems.Count == 0)
            {
                ImGui.PushFont(InterfaceManager.IconFont);
                ImGui.Text(FontAwesomeIcon.Check.ToIconString());
                ImGui.PopFont();
                ImGui.SameLine();
                ImGui.TextColoredWrapped(ImGuiColors.SuccessForeground, "无开发警告。"u8);
            }
            else
            {
                var numValidProblems = problems.Count(problem => devPlugin.DismissedValidationProblems.All(name => name != problem.GetType().Name));
                var shouldBother     = numValidProblems > 0;
                var validationIssuesText = shouldBother ?
                                               $"共 {numValidProblems} 条开发警告。" :
                                               $"已忽略 {problems.Count} 条开发警告。";

                using var col = ImRaii.PushColor
                (
                    ImGuiCol.Text,
                    shouldBother ?
                        ImGuiColors.WarningForeground :
                        ImGuiColors.DalamudGrey
                );
                using var tree = ImRaii.TreeNode($"{validationIssuesText}###validationIssueCollapsible");

                if (tree.Success)
                {
                    foreach (var problem in problems)
                    {
                        var thisProblemIsDismissed = devPlugin.DismissedValidationProblems.Contains(problem.GetType().Name);

                        if (!thisProblemIsDismissed)
                        {
                            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudWhite))
                            {
                                if (ImGuiComponents.IconButton
                                    (
                                        $"##dismissValidationIssue{problem.GetType().Name}",
                                        FontAwesomeIcon.TimesCircle
                                    ))
                                {
                                    devPlugin.DismissedValidationProblems.Add(problem.GetType().Name);
                                    Service<DalamudConfiguration>.Get().QueueSave();
                                }

                                if (ImGui.IsItemHovered())
                                {
                                    ImGui.SetTooltip("忽略");
                                }
                            }

                            ImGui.SameLine();
                        }

                        var iconColor = problem.Severity switch
                        {
                            PluginValidator.ValidationSeverity.Fatal       => ImGuiColors.ErrorForeground,
                            PluginValidator.ValidationSeverity.Warning     => ImGuiColors.WarningForeground,
                            PluginValidator.ValidationSeverity.Information => ImGuiColors.InfoForeground,
                            _                                              => ImGuiColors.DalamudGrey
                        };

                        using (ImRaii.PushColor(ImGuiCol.Text, iconColor))
                        using (ImRaii.PushFont(InterfaceManager.IconFont))
                        {
                            switch (problem.Severity)
                            {
                                case PluginValidator.ValidationSeverity.Fatal:
                                    ImGui.Text(FontAwesomeIcon.TimesCircle.ToIconString());
                                    break;
                                case PluginValidator.ValidationSeverity.Warning:
                                    ImGui.Text(FontAwesomeIcon.ExclamationTriangle.ToIconString());
                                    break;
                                case PluginValidator.ValidationSeverity.Information:
                                    ImGui.Text(FontAwesomeIcon.InfoCircle.ToIconString());
                                    break;
                                default:
                                    throw new ArgumentOutOfRangeException(nameof(devPlugin), problem.Severity, "未知的插件检查级别");
                            }
                        }

                        ImGui.SameLine();

                        using (ImRaii.PushColor
                               (
                                   ImGuiCol.Text,
                                   thisProblemIsDismissed ?
                                       ImGuiColors.DalamudGrey :
                                       ImGuiColors.DalamudWhite
                               ))
                        {
                            ImGui.TextWrapped(problem.GetLocalizedDescription());
                        }
                    }
                }
            }
        }
    }

    private static void DrawDevPluginButtons
    (
        LocalPlugin localPlugin
    )
    {
        ImGui.SameLine();

        var configuration = Service<DalamudConfiguration>.Get();

        if (localPlugin is LocalDevPlugin plugin)
        {
            var isInDefaultProfile =
                Service<ProfileManager>.Get().IsInDefaultProfile(localPlugin.EffectiveWorkingPluginId);

            // https://colorswall.com/palette/2868/
            var greenColor = new Vector4(0x5C, 0xB8, 0x5C, 0xFF) / 0xFF;
            var redColor   = new Vector4(0xD9, 0x53, 0x4F, 0xFF) / 0xFF;

            // Load on boot
            using (ImRaii.Disabled(!isInDefaultProfile))
            {
                ImGui.PushStyleColor
                (
                    ImGuiCol.Button,
                    plugin.StartOnBoot ?
                        greenColor :
                        redColor
                );
                ImGui.PushStyleColor
                (
                    ImGuiCol.ButtonHovered,
                    plugin.StartOnBoot ?
                        greenColor :
                        redColor
                );

                ImGui.SameLine();

                if (ImGuiComponents.IconButton(FontAwesomeIcon.PowerOff))
                {
                    plugin.StartOnBoot ^= true;
                    configuration.QueueSave();
                }

                ImGui.PopStyleColor(2);

                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip
                    (
                        isInDefaultProfile ?
                            "启动时自动加载" :
                            "此插件已加入一个或多个合集，如需启用或禁用，请通过启用或禁用对应合集来操作\n如需手动管理，请先将其从所有合集中移除"
                    );
                }
            }

            // Automatic reload
            ImGui.PushStyleColor
            (
                ImGuiCol.Button,
                plugin.AutomaticReload ?
                    greenColor :
                    redColor
            );
            ImGui.PushStyleColor
            (
                ImGuiCol.ButtonHovered,
                plugin.AutomaticReload ?
                    greenColor :
                    redColor
            );

            ImGui.SameLine();

            if (ImGuiComponents.IconButton(FontAwesomeIcon.SyncAlt))
            {
                plugin.AutomaticReload ^= true;
                configuration.QueueSave();
            }

            ImGui.PopStyleColor(2);

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip("自动重新加载");
            }

            // Error Notifications
            ImGui.PushStyleColor
            (
                ImGuiCol.Button,
                plugin.NotifyForErrors ?
                    greenColor :
                    redColor
            );
            ImGui.PushStyleColor
            (
                ImGuiCol.ButtonHovered,
                plugin.NotifyForErrors ?
                    greenColor :
                    redColor
            );

            ImGui.SameLine();

            if (ImGuiComponents.IconButton(FontAwesomeIcon.Bolt))
            {
                plugin.NotifyForErrors ^= true;
                configuration.QueueSave();
            }

            ImGui.PopStyleColor(2);

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip("当此插件产生错误时显示 Dalamud 通知");
            }
        }
    }
}
