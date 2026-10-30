using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Console;
using Dalamud.Game.Command;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private void DrawAvailablePlugin
    (
        RemotePluginManifest manifest,
        int                  index
    )
    {
        var pluginKey = $"available:{manifest.SourceRepo.PluginMasterUrl}:{manifest.InternalName}";
        if (this.ClipPluginItem(pluginKey))
            return;

        var startY        = ImGui.GetCursorPosY();
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var canUseTesting = pluginManager.CanUseTesting(manifest);
        var useTesting    = pluginManager.UseTesting(manifest);
        var wasSeen       = WasPluginSeen(manifest.InternalName);

        var isOutdated     = IsAvailableManifestOutdated(manifest, useTesting);
        var isIncompatible = IsAvailableManifestIncompatible(manifest);

        var enableInstallButton = this.updateStatus  != OperationStatus.InProgress &&
                                  this.installStatus != OperationStatus.InProgress &&
                                  pluginManager.ReposReady                         &&
                                  this.availablePluginsChanged == 0                &&
                                  !isOutdated                                      &&
                                  !isIncompatible;

        // Check for valid versions
        if ((useTesting && manifest.TestingAssemblyVersion == null) || manifest.AssemblyVersion == null)
        {
            // Without a valid version, quit
            return;
        }

        // Name
        var label = manifest.Name;

        // Testing
        if (useTesting)
        {
            label += " （测试版）";
        }
        else if (ShouldRenderAsTestingExclusive(manifest))
        {
            label += " （仅限测试版）";
        }
        else if (canUseTesting)
        {
            label += " （存在测试版）";
        }

        if (isIncompatible)
        {
            label += " （不兼容）";
        }

        var isThirdParty = manifest.SourceRepo.IsThirdParty;

        ImGui.PushID($"available{index}{manifest.InternalName}");

        var flags = PluginHeaderFlags.None;
        if (isThirdParty)
            flags |= PluginHeaderFlags.IsThirdParty;
        if (!wasSeen)
            flags |= PluginHeaderFlags.IsNew;
        if (isOutdated)
            flags |= PluginHeaderFlags.IsInstallableOutdated;
        if (useTesting || manifest.IsTestingExclusive)
            flags |= PluginHeaderFlags.IsTesting;
        if (isIncompatible)
            flags |= PluginHeaderFlags.IsIncompatible;

        if (this.DrawPluginCollapsingHeader(label, null, manifest, flags, () => this.DrawAvailablePluginContextMenu(manifest), index))
        {
            if (!wasSeen)
                configuration.SeenPluginInternalName.Add(manifest.InternalName);

            ImGuiHelpers.ScaledDummy(5);

            ImGui.Indent();

            // Installable from (点击复制)
            var repoText = manifest.SourceRepo.IsThirdParty ?
                               $"来源：{manifest.SourceRepo.PluginMasterUrl}" :
                               $"来源：官方插件库（{manifest.SourceRepo.PluginMasterUrl}）";
            ImGui.TextColored(ImGuiColors.DalamudGrey3, repoText);
            if (ImGui.IsItemHovered())
                ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

            if (ImGui.IsItemClicked())
            {
                ImGui.SetClipboardText(manifest.SourceRepo.PluginMasterUrl);
                Service<NotificationManager>.Get().AddNotification
                    ("复制了仓库链接到剪贴板。", "已复制", NotificationType.Success);
            }

            ImGuiHelpers.ScaledDummy(2);

            // Description
            if (!string.IsNullOrWhiteSpace(manifest.Description))
            {
                ImGui.TextWrapped(manifest.Description);
            }

            ImGuiHelpers.ScaledDummy(5);

            var versionString = useTesting ?
                                    $"{manifest.TestingAssemblyVersion}" :
                                    $"{manifest.AssemblyVersion}";

            if (pluginManager.SafeMode)
            {
                ImGuiComponents.DisabledButton("安全模式下无法更改");
            }
            else if (!enableInstallButton)
            {
                ImGuiComponents.DisabledButton
                (
                    pluginManager.ReposReady ?
                        $"安装 v{versionString}" :
                        "等待刷新后安装"
                );
            }
            else
            {
                using var color      = ImRaii.PushColor(ImGuiCol.Button, ImGuiColors.DalamudRed.Darken(0.3f).Fade(0.4f));
                var       buttonText = $"安装 v{versionString}";

                if (ImGui.Button($"{buttonText}##{buttonText}{index}"))
                {
                    this.StartInstall(manifest, useTesting);
                }
            }

            ImGui.SameLine();
            ImGuiHelpers.ScaledDummy(10);
            ImGui.SameLine();

            if (this.DrawVisitRepoUrlButton(manifest.RepoUrl, true))
            {
                ImGui.SameLine();
                ImGuiHelpers.ScaledDummy(3);
            }

            if (!manifest.SourceRepo.IsThirdParty && manifest.AcceptsFeedback && !isOutdated)
            {
                ImGui.SameLine();
                this.DrawSendFeedbackButton(manifest, false, true);
            }

            ImGuiHelpers.ScaledDummy(5);

            if (this.DrawPluginImages(null, manifest, isThirdParty, index))
                ImGuiHelpers.ScaledDummy(5);

            ImGui.Unindent();
        }

        ImGui.PopID();
        this.pluginItemHeights[pluginKey] = ImGui.GetCursorPosY() - startY;
    }

    private void DrawInstalledPlugin
    (
        LocalPlugin            plugin,
        int                    index,
        RemotePluginManifest?  remoteManifest,
        AvailablePluginUpdate? availablePluginUpdate,
        bool                   showInstalled
    )
    {
        var pluginKey = $"installed:{plugin.EffectiveWorkingPluginId}:{showInstalled}";
        if (this.ClipPluginItem(pluginKey))
            return;

        var startY         = ImGui.GetCursorPosY();
        var configuration  = Service<DalamudConfiguration>.Get();
        var commandManager = Service<CommandManager>.Get();

        var testingOptIn =
            configuration.PluginTestingOptIns?.FirstOrDefault(x => x.InternalName == plugin.Manifest.InternalName);
        var trouble = false;

        // Name
        var label = plugin.Manifest.Name;

        // Testing
        if (ShouldRenderAsTestingExclusive(remoteManifest))
        {
            label += " （仅限测试版）";
        }
        else if (plugin.IsTesting)
        {
            label += " （测试版）";
        }

        var hasTestingAvailable = this.pluginListAvailable.Any(x => x.InternalName == plugin.InternalName && x.IsAvailableForTesting);

        if (hasTestingAvailable && configuration.DoPluginTest && testingOptIn == null)
        {
            label += " （存在测试版）";
        }

        // Installed (for the all plugins list)
        if (showInstalled)
        {
            label += " （已安装）";
        }

        // Disabled
        if (!plugin.IsWantedByAnyProfile || !plugin.CheckPolicy())
        {
            label   += " （已禁用）";
            trouble =  true;
        }

        // Load error
        if (plugin.State is PluginState.LoadError or PluginState.DependencyResolutionFailed &&
            plugin.CheckPolicy()                                                            &&
            !plugin.IsOutdated                                                              &&
            !plugin.IsBanned                                                                &&
            !plugin.IsOrphaned)
        {
            label   += " （加载失败）";
            trouble =  true;
        }

        // Unload error
        if (plugin.State == PluginState.UnloadError)
        {
            label   += " （卸载错误）";
            trouble =  true;
        }

        // Dev plugins can never update
        if (plugin.IsDev)
            availablePluginUpdate = null;

        // Update available
        if (availablePluginUpdate != null)
        {
            label += " （可更新）";
        }

        // Freshly updated
        var thisWasUpdated = false;

        if (this.updatedPlugins != null && !plugin.IsDev)
        {
            var update = this.updatedPlugins.FirstOrDefault(update => update.AffectedPlugin.InternalName == plugin.Manifest.InternalName);

            if (update != null)
            {
                if (update.Status == PluginUpdateStatus.StatusKind.Success)
                {
                    thisWasUpdated =  true;
                    label          += " （已更新）";
                }
                else
                {
                    label += " （更新失败）";
                }
            }
        }

        // Outdated API level
        if (plugin.IsOutdated)
        {
            label   += " （API 版本不对应）";
            trouble =  true;
        }

        // Banned
        if (plugin.IsBanned)
        {
            label   += " （自动禁用）";
            trouble =  true;
        }

        // Out of service
        if (plugin.IsDecommissioned && !plugin.IsOrphaned)
        {
            label   += " （已过时）";
            trouble =  true;
        }

        // Scheduled for deletion
        if (plugin.Manifest.ScheduledForDeletion)
        {
            label += " （计划删除）";
        }

        ImGui.PushID($"installed{index}{plugin.Manifest.InternalName}");

        var applicableChangelog = plugin.IsTesting ?
                                      remoteManifest?.TestingChangelog :
                                      remoteManifest?.Changelog;
        var hasChangelog                                = !applicableChangelog.IsNullOrWhitespace();
        var didDrawApplicableChangelogInsideCollapsible = false;

        Version? availablePluginUpdateVersion               = null;
        string?  availableChangelog                         = null;
        var      didDrawAvailableChangelogInsideCollapsible = false;

        if (availablePluginUpdate != null)
        {
            availablePluginUpdateVersion =
                availablePluginUpdate.UseTesting ?
                    availablePluginUpdate.UpdateManifest.TestingAssemblyVersion :
                    availablePluginUpdate.UpdateManifest.AssemblyVersion;

            availableChangelog =
                availablePluginUpdate.UseTesting ?
                    availablePluginUpdate.UpdateManifest.TestingChangelog :
                    availablePluginUpdate.UpdateManifest.Changelog;
        }

        var flags = PluginHeaderFlags.None;
        if (plugin.IsThirdParty)
            flags |= PluginHeaderFlags.IsThirdParty;
        if (trouble)
            flags |= PluginHeaderFlags.HasTrouble;
        if (availablePluginUpdate != null)
            flags |= PluginHeaderFlags.UpdateAvailable;
        if (plugin.IsOrphaned)
            flags |= PluginHeaderFlags.IsOrphan;
        if (plugin.IsTesting)
            flags |= PluginHeaderFlags.IsTesting;

        if (this.DrawPluginCollapsingHeader
                (label, plugin, plugin.Manifest, flags, () => this.DrawInstalledPluginContextMenu(plugin, remoteManifest, testingOptIn), index))
        {
            if (!WasPluginSeen(plugin.Manifest.InternalName))
                configuration.SeenPluginInternalName.Add(plugin.Manifest.InternalName);

            var manifest = plugin.Manifest;

            ImGui.Indent();

            // Name
            ImGui.Text(manifest.Name);

            // Download count
            var downloadText = $" 作者：{manifest.Author}";
            if (!plugin.IsDev &&
                manifest.DownloadCount > 0)
                downloadText += $"（{manifest.DownloadCount:N0} 次下载）";

            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadText);

            var isThirdParty = plugin.IsThirdParty;

            // Installed from
            if (plugin.IsDev)
            {
                var fileText = $"来源：{plugin.DllFile.FullName}";
                ImGui.TextColored(ImGuiColors.DalamudGrey3, fileText);
            }
            else if (plugin.IsThirdParty)
            {
                var repoText = $"来源：{manifest.InstalledFromUrl}";
                ImGui.TextColored(ImGuiColors.DalamudGrey3, repoText);
                if (ImGui.IsItemHovered())
                    ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

                if (ImGui.IsItemClicked())
                {
                    ImGui.SetClipboardText(manifest.InstalledFromUrl);
                    Service<NotificationManager>.Get().AddNotification
                        ("复制了仓库链接到剪贴板。", "已复制", NotificationType.Success);
                }
            }
            else
            {
                var repoText = $"来源：官方插件库（{manifest.InstalledFromUrl}）";
                ImGui.TextColored(ImGuiColors.DalamudGrey3, repoText);
            }

            // Description
            if (!string.IsNullOrWhiteSpace(manifest.Description))
            {
                ImGui.TextWrapped(manifest.Description);
            }

            // Working Plugin ID
            if (this.hasDevPlugins)
            {
                ImGuiHelpers.ScaledDummy(3);
                ImGui.TextColored(ImGuiColors.DalamudGrey, $"插件生效标识符：{plugin.EffectiveWorkingPluginId}");
                ImGui.TextColored(ImGuiColors.DalamudGrey, $"命名空间：{ConsoleManagerPluginUtil.GetSanitizedNamespaceName(plugin.InternalName)}");
                ImGuiHelpers.ScaledDummy(3);
            }

            // Available commands (if loaded)
            if (plugin.IsLoaded)
            {
                var commands = commandManager.Commands
                                             .Where
                                             (cInfo =>
                                                  cInfo.Value is { ShowInHelp: true } &&
                                                  commandManager.GetHandlerAssemblyName(cInfo.Key, cInfo.Value) == plugin.Manifest.InternalName
                                             )
                                             .ToList();

                if (commands.Count > 0)
                {
                    ImGui.Dummy(ImGuiHelpers.ScaledVector2(10f, 10f));

                    foreach (var command in commands
                                            .OrderBy(cInfo => cInfo.Value.DisplayOrder)
                                            .ThenBy(cInfo => cInfo.Key))
                    {
                        ImGui.TextWrapped($"{command.Key} → {command.Value.HelpMessage}");
                    }

                    ImGuiHelpers.ScaledDummy(3);
                }
            }

            if (plugin is LocalDevPlugin devPlugin)
            {
                DrawDevPluginValidationIssues(devPlugin);
                ImGuiHelpers.ScaledDummy(5);
            }

            // Controls
            this.DrawPluginControlButton(plugin, availablePluginUpdate);
            DrawDevPluginButtons(plugin);
            this.DrawVisitRepoUrlButton(plugin.Manifest.RepoUrl, false);
            this.DrawDeletePluginButton(plugin);

            if (availablePluginUpdate != null && !plugin.IsDev)
            {
                ImGui.SameLine();
                this.DrawUpdateSinglePluginButton(availablePluginUpdate);
            }

            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.DalamudGrey3, $" v{plugin.EffectiveVersion}");

            ImGuiHelpers.ScaledDummy(5);

            if (this.DrawPluginImages(plugin, manifest, isThirdParty, index))
                ImGuiHelpers.ScaledDummy(5);

            ImGui.Unindent();

            if (hasChangelog)
            {
                if (ImGui.TreeNode($"更新日志（v{plugin.EffectiveVersion}）"))
                {
                    didDrawApplicableChangelogInsideCollapsible = true;
                    this.DrawInstalledPluginChangelog(applicableChangelog);
                    ImGui.TreePop();
                }
            }

            if (!availableChangelog.IsNullOrWhitespace() && ImGui.TreeNode($"可用更新日志（v{availablePluginUpdateVersion}）"))
            {
                this.DrawInstalledPluginChangelog(availableChangelog);
                ImGui.TreePop();
                didDrawAvailableChangelogInsideCollapsible = true;
            }
        }

        if (thisWasUpdated &&
            hasChangelog   &&
            !didDrawApplicableChangelogInsideCollapsible)
        {
            this.DrawInstalledPluginChangelog(applicableChangelog);
        }

        if (this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.UpdateablePlugins &&
            !availableChangelog.IsNullOrWhitespace()                                                         &&
            !didDrawAvailableChangelogInsideCollapsible)
        {
            this.DrawInstalledPluginChangelog(availableChangelog);
        }

        ImGui.PopID();
        this.pluginItemHeights[pluginKey] = ImGui.GetCursorPosY() - startY;
    }

    private void DrawInstalledPluginChangelog
    (
        string changelog
    )
    {
        ImGuiHelpers.ScaledDummy(5);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, this.changelogBgColor);
        ImGui.PushStyleColor(ImGuiCol.Text,    this.changelogTextColor);

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(7, 5));

        if (ImGui.BeginChild
                ("##changelog"u8, new Vector2(-1, 100), true, ImGuiWindowFlags.NoNavFocus | ImGuiWindowFlags.NoNavInputs | ImGuiWindowFlags.AlwaysAutoResize))
        {
            ImGui.Text("更新日志："u8);
            ImGuiHelpers.ScaledDummy(2);
            ImGui.TextWrapped(changelog!);
        }

        ImGui.EndChild();

        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
    }

    private bool DrawVisitRepoUrlButton
    (
        string? repoUrl,
        bool    big
    )
    {
        if (!string.IsNullOrEmpty(repoUrl) && repoUrl.StartsWith("https://"))
        {
            ImGui.SameLine();

            var clicked = big ?
                              ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Globe, "插件主页") :
                              ImGuiComponents.IconButton(FontAwesomeIcon.Globe);

            if (clicked)
            {
                try
                {
                    _ = Process.Start
                    (
                        new ProcessStartInfo
                        {
                            FileName        = repoUrl,
                            UseShellExecute = true
                        }
                    );
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Could not open repository URL {RepoUrl}", repoUrl);
                }
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("访问插件主页");

            return true;
        }

        return false;
    }

    private bool DrawPluginImages
    (
        LocalPlugin?    plugin,
        IPluginManifest manifest,
        bool            isThirdParty,
        int             index
    )
    {
        var hasImages = this.imageCache.TryGetImages(plugin, manifest, isThirdParty, out var imageTextures);
        if (!hasImages || imageTextures.All(x => x == null))
            return false;

        const float THUMB_FACTOR = 2.7f;

        const int SCROLL_BAR_SIZE = 15;
        ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, SCROLL_BAR_SIZE);
        ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, Vector4.Zero);

        var width = ImGui.GetWindowWidth();

        if (ImGui.BeginChild
            (
                $"plugin{index}ImageScrolling",
                new Vector2(width - (70 * ImGuiHelpers.GlobalScale), (PluginImageCache.PluginImageHeight / THUMB_FACTOR) + SCROLL_BAR_SIZE),
                false,
                ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse | ImGuiWindowFlags.NoBackground
            ))
        {
            for (var i = 0; i < imageTextures.Length; i++)
            {
                var image = imageTextures[i];
                if (image == null)
                    continue;

                ImGui.PushStyleVar(ImGuiStyleVar.PopupBorderSize, 0);
                ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding,   Vector2.Zero);
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,    Vector2.Zero);

                var popupId = $"plugin{index}image{i}";

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

                if (i < imageTextures.Length - 1)
                {
                    ImGui.SameLine();
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.SameLine();
                }
            }
        }

        ImGui.EndChild();

        ImGui.PopStyleVar();
        ImGui.PopStyleColor();

        return true;
    }
}
