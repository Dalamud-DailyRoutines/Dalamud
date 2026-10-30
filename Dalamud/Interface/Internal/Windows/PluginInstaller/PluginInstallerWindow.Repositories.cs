using System.Collections.Generic;
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
using Dalamud.Plugin;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Profiles;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private PluginRepository? retryingRepo;

    private struct RepoSideBarState
    {
        public Vector2 GroupStartScreen;
        public float   ContentStartY;
        public float   BarWidthNarrow;
        public float   BarPadding;
        public uint    BarColorU32;
        public float   BarR;
        public float   BarG;
        public float   BarB;
        public string  RepoUrl;
        public bool    IsCollapsed;
    }

    private static List<IGrouping<string, T>> SortRepositoryGroups<T>
    (
        IEnumerable<IGrouping<string, T>> groups
    )
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pinnedOrder   = new Dictionary<string, int>(StringComparer.Ordinal);
        var bottomOrder   = new Dictionary<string, int>(StringComparer.Ordinal);

        for (var index = 0; index < configuration.PinnedRepoUrls.Count; index++)
            pinnedOrder[configuration.PinnedRepoUrls[index]] = index;

        for (var index = 0; index < configuration.BottomPinnedRepoUrls.Count; index++)
            bottomOrder[configuration.BottomPinnedRepoUrls[index]] = index;

        return
        [
            .. groups.OrderBy
                     (group =>
                         {
                             if (bottomOrder.ContainsKey(group.Key))
                                 return 2;
                             return pinnedOrder.ContainsKey(group.Key) ?
                                        0 :
                                        1;
                         }
                     ).ThenBy(group => bottomOrder.GetValueOrDefault(group.Key, pinnedOrder.GetValueOrDefault(group.Key)))
                     .ThenBy(group => group.Key, StringComparer.Ordinal)
        ];
    }

    private RepoSideBarState BeginRepoSideBar
    (
        string repoUrl
    )
    {
        var   hash = (uint)repoUrl.GetHashCode();
        var   hue  = hash % 360 / 360f;
        float barR = 0f, barG = 0f, barB = 0f;
        ImGui.ColorConvertHSVtoRGB(hue, 0.6f, 0.8f, ref barR, ref barG, ref barB);
        var barColorU32 = ImGui.ColorConvertFloat4ToU32(new Vector4(barR, barG, barB, 1f));

        var barWidthNarrow = 4f * ImGuiHelpers.GlobalScale;
        var barPadding     = 6f * ImGuiHelpers.GlobalScale;
        var isCollapsed    = this.collapsedRepoGroups.Contains(repoUrl);

        var state = new RepoSideBarState
        {
            GroupStartScreen = ImGui.GetCursorScreenPos(),
            ContentStartY    = ImGui.GetCursorPosY(),
            BarWidthNarrow   = barWidthNarrow,
            BarPadding       = barPadding,
            BarColorU32      = barColorU32,
            BarR             = barR,
            BarG             = barG,
            BarB             = barB,
            RepoUrl          = repoUrl,
            IsCollapsed      = isCollapsed
        };

        if (isCollapsed)
        {
            // 折叠态: 绘制一条横向颜色条, 显示来源信息
            var frameHeight  = ImGui.GetFrameHeight();
            var availWidth   = ImGui.GetContentRegionAvail().X;
            var cursorScreen = ImGui.GetCursorScreenPos();

            var wdl     = ImGui.GetWindowDrawList();
            var bgColor = ImGui.ColorConvertFloat4ToU32(new Vector4(barR * 0.2f, barG * 0.2f, barB * 0.2f, 0.85f));
            wdl.AddRectFilled(cursorScreen, cursorScreen + new Vector2(availWidth, frameHeight), bgColor, 3f);
            wdl.AddRect(cursorScreen, cursorScreen       + new Vector2(availWidth, frameHeight), barColorU32, 3f);

            var textPadding = 8f * ImGuiHelpers.GlobalScale;
            wdl.AddText(cursorScreen + new Vector2(textPadding, (frameHeight - ImGui.GetTextLineHeight()) * 0.5f), barColorU32, repoUrl);

            // 占位
            ImGui.Dummy(new Vector2(availWidth, frameHeight));

            // 双击展开
            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip("双击还原展开");

                if (ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
                {
                    this.collapsedRepoGroups.Remove(repoUrl);
                }
            }
        }
        else
        {
            ImGui.Indent(barWidthNarrow + barPadding);
        }

        return state;
    }

    private void EndRepoSideBar
    (
        in RepoSideBarState state
    )
    {
        if (state.IsCollapsed)
        {
            ImGuiHelpers.ScaledDummy(4);
            return;
        }

        ImGui.Unindent(state.BarWidthNarrow + state.BarPadding);

        var contentEndY = ImGui.GetCursorPosY();
        var groupHeight = contentEndY - state.ContentStartY;
        if (groupHeight < 1f)
            groupHeight = ImGui.GetTextLineHeightWithSpacing();

        var wdl            = ImGui.GetWindowDrawList();
        var barTopLeft     = state.GroupStartScreen;
        var barBottomRight = barTopLeft + new Vector2(state.BarWidthNarrow, groupHeight);
        wdl.AddRectFilled(barTopLeft, barBottomRight, state.BarColorU32, 2f);

        // 悬浮检测: 仅侧边条本身的窄条区域可交互
        var hoverWidth = state.BarWidthNarrow + state.BarPadding;
        var mousePos   = ImGui.GetMousePos();
        var isHovered = mousePos.X >= barTopLeft.X              &&
                        mousePos.X <= barTopLeft.X + hoverWidth &&
                        mousePos.Y >= barTopLeft.Y              &&
                        mousePos.Y <= barTopLeft.Y + groupHeight;

        var isFocused = ImGui.IsWindowFocused(ImGuiFocusedFlags.RootWindow);
        var isVisible = ImGui.IsRectVisible(barTopLeft, barBottomRight);

        if (isHovered && isFocused && isVisible)
        {
            var          fgDl          = ImGui.GetForegroundDrawList();
            var          textPadding   = 8f * ImGuiHelpers.GlobalScale;
            var          displayText   = state.RepoUrl;
            const string HINT_TEXT     = "（右键打开更多操作菜单）";
            var          textSize      = ImGui.CalcTextSize(displayText);
            var          hintSize      = ImGui.CalcTextSize(HINT_TEXT);
            var          overlayWidth  = MathF.Max(textSize.X, hintSize.X) + (textPadding * 2);
            var          overlayHeight = (ImGui.GetTextLineHeightWithSpacing()            * 2) + (textPadding * 2);

            var overlayTopLeft     = mousePos       + new Vector2(12f * ImGuiHelpers.GlobalScale, 12f * ImGuiHelpers.GlobalScale);
            var overlayBottomRight = overlayTopLeft + new Vector2(overlayWidth,                   overlayHeight);

            var bgColor = ImGui.ColorConvertFloat4ToU32(new Vector4(state.BarR * 0.15f, state.BarG * 0.15f, state.BarB * 0.15f, 0.95f));
            fgDl.AddRectFilled(overlayTopLeft, overlayBottomRight, bgColor, 4f);
            fgDl.AddRect(overlayTopLeft, overlayBottomRight, state.BarColorU32, 4f);

            var textPos = overlayTopLeft + new Vector2(textPadding, textPadding);
            fgDl.AddText(textPos, state.BarColorU32, displayText);

            var hintPos   = textPos + new Vector2(0, ImGui.GetTextLineHeightWithSpacing());
            var hintColor = ImGui.ColorConvertFloat4ToU32(ImGuiColors.DalamudGrey3);
            fgDl.AddText(hintPos, hintColor, HINT_TEXT);

            if (ImGui.IsMouseClicked(ImGuiMouseButton.Left))
            {
                ImGui.SetClipboardText(state.RepoUrl);
                Service<NotificationManager>.Get().AddNotification
                    ("复制了仓库链接到剪贴板。", "已复制", NotificationType.Success);
            }

            // 右键菜单: 折叠该来源
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
            {
                ImGui.OpenPopup($"##RepoSideBarCtx_{state.RepoUrl}");
            }
        }

        using (var popup = ImRaii.Popup($"##RepoSideBarCtx_{state.RepoUrl}"))
        {
            if (popup.Success)
            {
                if (ImGui.MenuItem("折叠该来源的全部插件"))
                {
                    this.collapsedRepoGroups.Add(state.RepoUrl);
                }

                ImGui.Separator();

                var pluginManager  = Service<PluginManager>.Get();
                var profileManager = Service<ProfileManager>.Get();
                var notifications  = Service<NotificationManager>.Get();
                var config         = Service<DalamudConfiguration>.Get();

                // Pin / Unpin repo (top)
                var isRepoPinned = config.PinnedRepoUrls.Contains(state.RepoUrl);

                if (ImGui.MenuItem
                    (
                        isRepoPinned ?
                            "取消置顶该插件库" :
                            "置顶该插件库"
                    ))
                {
                    if (isRepoPinned)
                    {
                        config.PinnedRepoUrls.Remove(state.RepoUrl);
                    }
                    else
                    {
                        config.PinnedRepoUrls.Add(state.RepoUrl);
                        config.BottomPinnedRepoUrls.Remove(state.RepoUrl); // 互斥: 置顶时取消置底
                    }

                    config.QueueSave();
                }

                // Bottom-pin / Un-bottom-pin repo
                var isRepoBottomPinned = config.BottomPinnedRepoUrls.Contains(state.RepoUrl);

                if (ImGui.MenuItem
                    (
                        isRepoBottomPinned ?
                            "取消置底该插件库" :
                            "置底该插件库"
                    ))
                {
                    if (isRepoBottomPinned)
                    {
                        config.BottomPinnedRepoUrls.Remove(state.RepoUrl);
                    }
                    else
                    {
                        config.BottomPinnedRepoUrls.Add(state.RepoUrl);
                        config.PinnedRepoUrls.Remove(state.RepoUrl); // 互斥: 置底时取消置顶
                    }

                    config.QueueSave();
                }

                ImGui.Separator();

                var repoUrl = state.RepoUrl;
                var repoPlugins = this.pluginListInstalled
                                      .Where
                                      (p =>
                                          {
                                              if (repoUrl == "开发版插件")
                                                  return p.IsDev;
                                              if (p.IsDev)
                                                  return false;
                                              if (repoUrl == "主库")
                                                  return p.Manifest.InstalledFromUrl == SpecialPluginSource.MainRepo;
                                              return p.Manifest.InstalledFromUrl == repoUrl;
                                          }
                                      )
                                      .ToList();

                var canOperate = this.updateStatus        != OperationStatus.InProgress &&
                                 this.installStatus       != OperationStatus.InProgress &&
                                 this.enableDisableStatus != OperationStatus.InProgress &&
                                 !profileManager.IsBusy                                 &&
                                 !pluginManager.SafeMode;

                var enableable = repoPlugins.Where(p => !p.IsWantedByAnyProfile && !IsInstalledPluginUnsupported(p)).ToList();

                if (ImGui.MenuItem($"启用全部已安装插件（{enableable.Count}）", false, canOperate && enableable.Count > 0))
                {
                    this.enableDisableStatus  = OperationStatus.InProgress;
                    this.loadingIndicatorKind = LoadingIndicatorKind.EnablingSingle;
                    Task.Run
                    (async () =>
                        {
                            foreach (var plugin in enableable)
                            {
                                var profile = profileManager.Profiles
                                                            .FirstOrDefault(x => x.WantsPlugin(plugin.EffectiveWorkingPluginId) != null) ??
                                              profileManager.DefaultProfile;
                                await profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false);
                                await plugin.LoadAsync(PluginLoadReason.Installer);
                            }

                            notifications.AddNotification($"已启用 {enableable.Count} 个插件", "批量启用", NotificationType.Success);
                        }
                    ).ContinueWith
                    (task =>
                        {
                            this.enableDisableStatus = OperationStatus.Complete;
                            this.DisplayErrorContinuation(task, "批量启用插件失败，请检查日志。");
                        }
                    );
                }

                var disableable = repoPlugins.Where(p => p.IsWantedByAnyProfile && p.State == PluginState.Loaded).ToList();

                if (ImGui.MenuItem($"禁用全部已安装插件（{disableable.Count}）", false, canOperate && disableable.Count > 0))
                {
                    this.enableDisableStatus  = OperationStatus.InProgress;
                    this.loadingIndicatorKind = LoadingIndicatorKind.DisablingSingle;
                    Task.Run
                    (async () =>
                        {
                            foreach (var plugin in disableable)
                            {
                                var profiles = profileManager.Profiles.Where(profile => profile.WantsPlugin(plugin.EffectiveWorkingPluginId) != null).ToList();
                                await plugin.UnloadAsync();
                                foreach (var profile in profiles)
                                    await profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, false, false);
                            }

                            notifications.AddNotification($"已禁用 {disableable.Count} 个插件", "批量禁用", NotificationType.Success);
                        }
                    ).ContinueWith
                    (task =>
                        {
                            this.enableDisableStatus = OperationStatus.Complete;
                            this.DisplayErrorContinuation(task, "批量禁用插件失败，请检查日志。");
                        }
                    );
                }

                var updatable = this.pluginListUpdatable
                                    .Where(u => repoPlugins.Contains(u.InstalledPlugin))
                                    .ToList();

                if (ImGui.MenuItem
                    (
                        $"更新全部已安装插件（{updatable.Count}）",
                        false,
                        canOperate && pluginManager.ReposReady && this.availablePluginsChanged == 0 && updatable.Count > 0
                    ))
                {
                    this.updateStatus         = OperationStatus.InProgress;
                    this.loadingIndicatorKind = LoadingIndicatorKind.UpdatingAll;

                    Task.Run(() => pluginManager.UpdatePluginsAsync(updatable, false))
                        .ContinueWith
                        (task =>
                            {
                                this.updateStatus = OperationStatus.Complete;

                                if (!task.IsCompletedSuccessfully)
                                {
                                    this.updatedPlugins    = null;
                                    this.updatePluginCount = 0;
                                    this.DisplayErrorContinuation(task, "更新插件失败\n请重启游戏并重试，如果此错误再次出现，请向开发团队反馈");
                                }
                                else
                                {
                                    this.updatedPlugins    = [.. task.Result.Where(result => result.Status == PluginUpdateStatus.StatusKind.Success)];
                                    this.updatePluginCount = this.updatedPlugins.Count;
                                    var failures = task.Result.Where(result => result.Status != PluginUpdateStatus.StatusKind.Success).ToList();
                                    if (failures.Count > 0)
                                        this.ShowErrorModal
                                            ($"有 {failures.Count} 个插件更新失败：\n{string.Join("\n", failures.Select(result => result.AffectedPlugin.InternalName))}");

                                    var success = this.updatedPlugins;
                                    if (success.Count > 0)
                                        notifications.AddNotification($"已更新 {success.Count} 个插件", "批量更新", NotificationType.Success);
                                    else
                                        notifications.AddNotification("没有插件需要更新", "批量更新", NotificationType.Info);
                                }
                            }
                        );
                }
            }
        }

        ImGuiHelpers.ScaledDummy(4);
    }
}
