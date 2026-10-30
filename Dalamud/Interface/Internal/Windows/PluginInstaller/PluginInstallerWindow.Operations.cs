using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Player;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Exceptions;
using Dalamud.Plugin.Internal.Profiles;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private int updatePluginCount;

    private List<PluginUpdateStatus>? updatedPlugins;

    private OperationStatus installStatus = OperationStatus.Idle;

    private OperationStatus updateStatus = OperationStatus.Idle;

    private OperationStatus enableDisableStatus = OperationStatus.Idle;

    private Guid enableDisableWorkingPluginId = Guid.Empty;

    private LoadingIndicatorKind loadingIndicatorKind = LoadingIndicatorKind.Unknown;

    private enum OperationStatus
    {
        Idle,
        InProgress,
        Complete
    }

    private enum LoadingIndicatorKind
    {
        Unknown,
        EnablingSingle,
        DisablingSingle,
        UpdatingSingle,
        UpdatingAll,
        Installing,
        Manager,
        ProfilesLoading
    }

    private bool AnyOperationInProgress => this.installStatus       == OperationStatus.InProgress ||
                                           this.updateStatus        == OperationStatus.InProgress ||
                                           this.enableDisableStatus == OperationStatus.InProgress;

    /// <summary>
    /// Start a plugin install and handle errors visually.
    /// </summary>
    /// <param name="manifest">The manifest to install.</param>
    /// <param name="useTesting">Install the testing version.</param>
    public void StartInstall
    (
        RemotePluginManifest manifest,
        bool                 useTesting
    )
    {
        var pluginManager = Service<PluginManager>.Get();
        var notifications = Service<NotificationManager>.Get();

        if (this.AnyOperationInProgress ||
            this.disposed               ||
            pluginManager.SafeMode)
            return;

        this.installStatus        = OperationStatus.InProgress;
        this.loadingIndicatorKind = LoadingIndicatorKind.Installing;

        Task.Run
            (async () =>
                {
                    await pluginManager.WaitForReposAsync();
                    var currentManifest = pluginManager.AvailablePlugins.FirstOrDefault
                                          (candidate =>
                                               candidate.InternalName               == manifest.InternalName &&
                                               candidate.SourceRepo.PluginMasterUrl == manifest.SourceRepo.PluginMasterUrl
                                          ) ??
                                          throw new InvalidOperationException("刷新后已找不到此插件，请重新选择。");
                    return await pluginManager.InstallPluginAsync(currentManifest, useTesting || currentManifest.IsTestingExclusive, PluginLoadReason.Installer);
                }
            )
            .ContinueWith
            (task =>
                {
                    // There is no need to set as Complete for an individual plugin installation
                    this.installStatus = OperationStatus.Idle;

                    if (this.DisplayErrorContinuation(task, $"安装插件 {manifest.Name} 失败\n请重启游戏并重试，如果此错误再次出现，请联系插件作者"))
                    {
                        // Fine as long as we aren't in an error state
                        if (task.Result.State is PluginState.Loaded or PluginState.Unloaded)
                        {
                            notifications.AddNotification
                                ($"安装了“{manifest.Name}”。", "插件已安装", NotificationType.Success);
                        }
                        else
                        {
                            notifications.AddNotification
                                ($"安装“{manifest.Name}”失败。", "插件未安装", NotificationType.Error);
                            this.ShowErrorModal($"安装插件 {manifest.Name} 失败\n请重启游戏并重试，如果此错误再次出现，请联系插件作者");
                        }
                    }
                }
            );
    }

    /// <summary>
    /// A continuation task that displays any errors received into the error modal.
    /// </summary>
    /// <param name="task">The previous task.</param>
    /// <param name="state">An error message to be displayed.</param>
    /// <returns>A value indicating whether to continue with the next task.</returns>
    public bool DisplayErrorContinuation
    (
        Task   task,
        object state
    )
    {
        if (!task.IsFaulted && !task.IsCanceled)
            return true;

        var newErrorMessage = state as string;

        if (task.Exception != null)
        {
            foreach (var ex in task.Exception.InnerExceptions)
            {
                if (ex is PluginException)
                {
                    Log.Error(ex, "Plugin installer threw an error");
#if DEBUG
                    if (!string.IsNullOrEmpty(ex.Message))
                        newErrorMessage += $"\n\n{ex.Message}";
#endif
                }
                else
                {
                    Log.Error(ex, "Plugin installer threw an unexpected error");
#if DEBUG
                    if (!string.IsNullOrEmpty(ex.Message))
                        newErrorMessage += $"\n\n{ex.Message}";
#endif
                }
            }
        }

        if (task.IsCanceled)
            Log.Error("A task was cancelled");

        this.ShowErrorModal(newErrorMessage ?? "发生未知错误。");

        return false;
    }

    private static void EnsureHaveTestingOptIn
    (
        IPluginManifest manifest
    )
    {
        var configuration = Service<DalamudConfiguration>.Get();

        if (configuration.PluginTestingOptIns.Any(x => x.InternalName == manifest.InternalName))
            return;

        configuration.PluginTestingOptIns.Add(new PluginTestingOptIn(manifest.InternalName));
        configuration.QueueSave();
    }

    private static void DrawProgressBar<T>
    (
        IEnumerable<T> items,
        Func<T, bool>  pendingFunc,
        Func<T, bool>  totalFunc,
        Action<T>      renderPending
    )
    {
        var windowSize = ImGui.GetWindowSize();

        var numLoaded = 0;
        var total     = 0;

        var itemsArray = items as T[] ?? [.. items];
        var allPending = itemsArray.Where(pendingFunc)
                                   .ToArray();
        var allLoadedOrLoading = itemsArray.Count(totalFunc);

        // Cap number of items we show to avoid clutter
        const int MAX_SHOWN = 3;

        foreach (var repo in allPending.Take(MAX_SHOWN))
        {
            renderPending(repo);
        }

        ImGuiHelpers.ScaledDummy(10);

        numLoaded += allLoadedOrLoading - allPending.Length;
        total     += allLoadedOrLoading;

        if (numLoaded != total)
        {
            ImGui.SetCursorPosX(windowSize.X / 3);
            ImGui.ProgressBar(numLoaded      / (float)total, new Vector2(windowSize.X / 3, 50), $"{numLoaded}/{total}");
        }
    }

    private void DrawProgressOverlay()
    {
        var pluginManager  = Service<PluginManager>.Get();
        var profileManager = Service<ProfileManager>.Get();

        var isWaitingManager = !pluginManager.PluginsReady ||
                               !pluginManager.HasLoadedRepos;
        var isWaitingProfiles = profileManager.IsBusy;

        var isLoading = this.AnyOperationInProgress ||
                        isWaitingManager            ||
                        isWaitingProfiles;

        if (isWaitingManager)
            this.loadingIndicatorKind = LoadingIndicatorKind.Manager;
        else if (isWaitingProfiles)
            this.loadingIndicatorKind = LoadingIndicatorKind.ProfilesLoading;

        if (!isLoading)
            return;

        ImGui.SetCursorPos(Vector2.Zero);

        var windowSize  = ImGui.GetWindowSize();
        var titleHeight = ImGui.GetFontSize() + (ImGui.GetStyle().FramePadding.Y * 2);

        using var loadingChild = ImRaii.Child("###installerLoadingFrame"u8, new Vector2(-1, -1), false);

        if (loadingChild)
        {
            ImGui.GetWindowDrawList().PushClipRectFullScreen();
            ImGui.GetWindowDrawList().AddRectFilled
            (
                ImGui.GetWindowPos() + new Vector2(0, titleHeight),
                ImGui.GetWindowPos() + windowSize,
                ImGui.ColorConvertFloat4ToU32(new(0f, 0f, 0f, 0.8f * ImGui.GetStyle().Alpha)),
                ImGui.GetStyle().WindowRounding,
                ImDrawFlags.RoundCornersBottom
            );
            ImGui.PopClipRect();

            ImGui.SetCursorPosY(windowSize.Y / 2);

            switch (this.loadingIndicatorKind)
            {
                case LoadingIndicatorKind.Unknown:
                    ImGuiHelpers.CenteredText("加载中……");
                    break;
                case LoadingIndicatorKind.EnablingSingle:
                    ImGuiHelpers.CenteredText("启用插件中……");
                    break;
                case LoadingIndicatorKind.DisablingSingle:
                    ImGuiHelpers.CenteredText("禁用插件中……");
                    break;
                case LoadingIndicatorKind.UpdatingSingle:
                    ImGuiHelpers.CenteredText("更新插件中……");
                    break;
                case LoadingIndicatorKind.UpdatingAll:
                    ImGuiHelpers.CenteredText("批量更新插件中……");
                    break;
                case LoadingIndicatorKind.Installing:
                    ImGuiHelpers.CenteredText("安装插件中……");
                    break;
                case LoadingIndicatorKind.Manager:
                    var managerMessage = (pluginManager.PluginsReady, pluginManager.ReposReady) switch
                    {
                        (true, false) => "正在加载插件仓库……",
                        (false, true) => "正在加载已安装的插件……",
                        _             => "正在加载仓库与插件……"
                    };
                    ImGuiHelpers.CenteredText(managerMessage);

                    if (pluginManager.PluginsReady != pluginManager.ReposReady)
                    {
                        ImGuiHelpers.ScaledDummy(10);

                        if (pluginManager.PluginsReady)
                        {
                            DrawProgressBar
                            (
                                pluginManager.Repos,
                                repo => repo.IsEnabled && repo.State is not (PluginRepositoryState.Success or PluginRepositoryState.Fail),
                                repo => repo.IsEnabled,
                                repo => ImGuiHelpers.CenteredText($"正在加载 {repo.PluginMasterUrl}")
                            );
                        }
                        else
                        {
                            DrawProgressBar
                            (
                                pluginManager.InstalledPlugins,
                                plugin => plugin.State == PluginState.Loading,
                                plugin => plugin.State is PluginState.Loaded or PluginState.LoadError or PluginState.Loading,
                                plugin => ImGuiHelpers.CenteredText($"正在加载 {plugin.Name}……")
                            );
                        }
                    }

                    break;
                case LoadingIndicatorKind.ProfilesLoading:
                    ImGuiHelpers.CenteredText("应用合集中……");
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            if (DateTime.Now - this.timeLoaded > TimeSpan.FromSeconds(30) && !pluginManager.PluginsReady)
            {
                ImGuiHelpers.ScaledDummy(10);
                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.AttentionForeground);
                ImGuiHelpers.CenteredText("有插件正在阻止插件安装器加载。\n可以点击下方按钮以安全模式重启，然后删除相关插件。");
                ImGui.PopStyleColor();

                ImGuiHelpers.BeginHorizontalButtonGroup()
                            .Add
                            (
                                "以安全模式重启",
                                () =>
                                {
                                    var config = Service<DalamudConfiguration>.Get();
                                    config.PluginSafeMode = true;
                                    config.ForceSave();
                                    Dalamud.RestartGame();
                                }
                            )
                            .SetCentered(true)
                            .WithHeight(30)
                            .Draw();
            }
        }
    }

    private bool DrawPluginListLoading()
    {
        var pluginManager = Service<PluginManager>.Get();

        var ready = pluginManager.PluginsReady && pluginManager.HasLoadedRepos;

        if (!ready)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, "正在加载插件……");
        }

        if (pluginManager.ReposReady)
            this.retryingRepo = null;

        foreach (var repo in pluginManager.Repos)
        {
            if (repo.State != PluginRepositoryState.Fail && repo != this.retryingRepo)
                continue;

            using var id = ImRaii.PushId(repo.PluginMasterUrl);

            using (ImRaii.Disabled(!pluginManager.ReposReady || this.AnyOperationInProgress))
            {
                if (ImGui.SmallButton
                    (
                        repo == this.retryingRepo ?
                            "重试中……" :
                            "重试"
                    ))
                {
                    this.retryingRepo = repo;
                    _                 = pluginManager.ReloadRepoAsync(repo);
                }
            }

            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.ErrorForeground, $"下载失败（{repo.PluginMasterUrl}）");

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip
                (
                    repo.LastSuccessfulRefresh is { } lastRefresh ?
                        $"正在使用上次结果，最后成功刷新：{lastRefresh.ToLocalTime():yyyy-MM-dd HH:mm:ss}" :
                        "此仓库尚未成功加载。"
                );
            }

            ImGui.SameLine();
            if (ImGui.SmallButton("查看日志"))
                Service<DalamudInterface>.Get().OpenLogWindow();
        }

        return ready;
    }

    private void DrawAvailablePluginContextMenu
    (
        RemotePluginManifest manifest
    )
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var hasTestingVersionAvailable = configuration.DoPluginTest && manifest.IsAvailableForTesting;

        if (ImGui.BeginPopupContextItem("ItemContextMenu"u8))
        {
            if (hasTestingVersionAvailable)
            {
                using var disabled = ImRaii.Disabled
                    (!pluginManager.ReposReady || this.availablePluginsChanged != 0 || pluginManager.SafeMode || this.AnyOperationInProgress);

                if (ImGui.Selectable("安装测试版"))
                {
                    EnsureHaveTestingOptIn(manifest);
                    this.StartInstall(manifest, true);
                }

                ImGui.Separator();
            }

            if (ImGui.Selectable("标记全部为已查看"))
            {
                configuration.SeenPluginInternalName.AddRange(this.pluginListAvailable.Select(x => x.InternalName));
                configuration.QueueSave();
            }

            var isHidden = configuration.HiddenPluginInternalName.Contains(manifest.InternalName);

            switch (isHidden)
            {
                case false when ImGui.Selectable("隐藏"):
                    configuration.HiddenPluginInternalName.Add(manifest.InternalName);
                    configuration.QueueSave();
                    break;
                case true when ImGui.Selectable("取消隐藏"):
                    configuration.HiddenPluginInternalName.Remove(manifest.InternalName);
                    configuration.QueueSave();
                    break;
            }

            if (ImGui.Selectable("重置数据"))
            {
                this.ShowDeletePluginConfigWarningModal(manifest.Name).ContinueWith
                (t =>
                    {
                        var shouldDelete = t.Result;

                        if (shouldDelete)
                        {
                            Log.Debug("Deleting config for {InternalName}", manifest.InternalName);

                            this.installStatus = OperationStatus.InProgress;

                            Task.Run
                                (() =>
                                    {
                                        pluginManager.PluginConfigs.Delete(manifest.InternalName);
                                        var dir = pluginManager.PluginConfigs.GetDirectory(manifest.InternalName);

                                        if (Directory.Exists(dir))
                                            Directory.Delete(dir, true);
                                    }
                                )
                                .ContinueWith
                                (task =>
                                    {
                                        this.installStatus = OperationStatus.Idle;

                                        this.DisplayErrorContinuation(task, $"重置插件 {manifest.InternalName} 失败\n\n该插件可能不支持此操作，可尝试在游戏关闭时手动删除配置——请参阅常见问题解答");
                                    }
                                );
                        }
                    }
                );
            }

            ImGui.EndPopup();
        }
    }

    private unsafe void DrawInstalledPluginContextMenu
    (
        LocalPlugin           plugin,
        RemotePluginManifest? remoteManifest,
        PluginTestingOptIn?   optIn
    )
    {
        var pluginManager = Service<PluginManager>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        if (ImGui.BeginPopupContextItem("InstalledItemContextMenu"u8))
        {
            if (configuration.DoPluginTest)
            {
                using var disabled =
                    ImRaii.Disabled(remoteManifest == null || remoteManifest?.IsTestingExclusive == true);

                if (ImGui.MenuItem("接收测试版", optIn != null))
                {
                    if (optIn != null)
                    {
                        configuration.PluginTestingOptIns!.Remove(optIn);

                        // Warn about downgrade
                        if (remoteManifest?.TestingAssemblyVersion > remoteManifest?.AssemblyVersion)
                        {
                            this.testingWarningModalOnNextFrame = true;
                        }
                    }
                    else
                    {
                        EnsureHaveTestingOptIn(plugin.Manifest);
                    }

                    configuration.QueueSave();
                    _ = pluginManager.ReloadAllReposAsync();
                }
            }

            // Favorite
            var isFavorite = configuration.FavoritePluginInternalName.Contains(plugin.Manifest.InternalName);

            if (ImGui.MenuItem
                (
                    isFavorite ?
                        "取消收藏" :
                        "收藏"
                ))
            {
                if (isFavorite)
                    configuration.FavoritePluginInternalName.Remove(plugin.Manifest.InternalName);
                else
                    configuration.FavoritePluginInternalName.Add(plugin.Manifest.InternalName);
                configuration.QueueSave();
            }

            // Pinned
            var isPinned = configuration.PinnedPluginInternalName.Contains(plugin.Manifest.InternalName);

            if (ImGui.MenuItem
                (
                    isPinned ?
                        "取消置顶" :
                        "置顶"
                ))
            {
                if (isPinned)
                    configuration.PinnedPluginInternalName.Remove(plugin.Manifest.InternalName);
                else
                    configuration.PinnedPluginInternalName.Add(plugin.Manifest.InternalName);
                configuration.QueueSave();
                // Resort plugins to update pinned order
                this.ResortPlugins();
            }

            ImGui.Separator();

            // Open plugin folder
            if (configuration.DevMode == true && ImGui.MenuItem("打开插件文件夹"))
                Util.OpenLink(plugin.DllFile.Directory.ToString());

            // Open config file
            var configFile = pluginManager.PluginConfigs.GetConfigFile(plugin.InternalName);
            if (configFile.Exists && ImGui.MenuItem("打开配置文件"))
                Util.OpenLink(configFile.ToString());

            // Open config folder
            var configDir = pluginManager.PluginConfigs.GetConfigDirectory(plugin.InternalName);
            if (configDir.Exists && ImGui.MenuItem("打开配置文件夹"))
                Util.OpenLink(configDir.ToString());

            ImGui.Separator();

            if (ImGui.MenuItem("重置数据并重载插件"))
            {
                this.ShowDeletePluginConfigWarningModal(plugin.Manifest.Name, optIn != null).ContinueWith
                (t =>
                    {
                        var shouldDelete = t.Result;

                        if (shouldDelete)
                        {
                            Log.Debug("Deleting config for {InternalName}", plugin.Manifest.InternalName);

                            this.installStatus = OperationStatus.InProgress;

                            Task.Run(() => pluginManager.DeleteConfigurationAsync(plugin))
                                .ContinueWith
                                (task =>
                                    {
                                        this.installStatus = OperationStatus.Idle;

                                        this.DisplayErrorContinuation(task, $"重置插件 {plugin.Manifest.InternalName} 失败\n\n该插件可能不支持此操作，可尝试在游戏关闭时手动删除配置——请参阅常见问题解答");
                                    }
                                );
                        }
                    }
                );
            }

            ImGui.EndPopup();
        }
    }

    private void DrawPluginControlButton
    (
        LocalPlugin            plugin,
        AvailablePluginUpdate? availableUpdate
    )
    {
        var notifications  = Service<NotificationManager>.Get();
        var pluginManager  = Service<PluginManager>.Get();
        var profileManager = Service<ProfileManager>.Get();
        var config         = Service<DalamudConfiguration>.Get();

        var applicableForProfiles = plugin.Manifest.SupportsProfiles /*&& !plugin.IsDev*/;
        var profilesThatWantThisPlugin = profileManager.Profiles
                                                       .Where(x => x.WantsPlugin(plugin.EffectiveWorkingPluginId) != null)
                                                       .ToArray();
        var isInSingleProfile = profilesThatWantThisPlugin.Length == 1;
        var isDefaultPlugin   = profileManager.IsInDefaultProfile(plugin.EffectiveWorkingPluginId);

        // Disable everything if the updater is running or another plugin is operating
        var disabled = this.AnyOperationInProgress;

        // Disable everything if the plugin is outdated
        disabled = disabled || (plugin.IsOutdated && !plugin.IsDev) || plugin.IsBanned;

        // Disable everything if the plugin is orphaned
        // Control will immediately be disabled once the plugin is disabled
        disabled = disabled || (plugin.IsOrphaned && !plugin.IsLoaded);

        // Disable everything if the plugin failed to load
        // Now handled by the first case below
        // disabled = disabled || plugin.State == PluginState.LoadError || plugin.State == PluginState.DependencyResolutionFailed;

        // Disable everything if we're loading plugins
        disabled = disabled || plugin.State == PluginState.Loading || plugin.State == PluginState.Unloading;

        // Disable everything if we're applying profiles
        disabled = disabled || profileManager.IsBusy;

        var toggleId              = plugin.Manifest.InternalName;
        var isLoadedAndUnloadable = plugin.State is PluginState.Loaded or PluginState.DependencyResolutionFailed;

        // StyleModelV1.DalamudStandard.Push();

        var profileChooserPopupName = $"###pluginProfileChooser{plugin.Manifest.InternalName}";

        if (ImGui.BeginPopup(profileChooserPopupName))
        {
            var didAny = false;

            foreach (var profile in profileManager.Profiles.Where(x => !x.IsDefaultProfile))
            {
                var inProfile = profile.WantsPlugin(plugin.EffectiveWorkingPluginId) != null;

                if (ImGui.Checkbox($"###profilePick{profile.Guid}{plugin.Manifest.InternalName}", ref inProfile))
                {
                    if (inProfile)
                    {
                        Task.Run(() => profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true))
                            .ContinueWith(this.DisplayErrorContinuation, "无法将插件添加到此合集");
                    }
                    else
                    {
                        Task.Run(() => profile.RemoveAsync(plugin.EffectiveWorkingPluginId))
                            .ContinueWith(this.DisplayErrorContinuation, "无法从此合集中移除插件");
                    }
                }

                ImGui.SameLine();

                ImGui.Text(profile.Name);

                didAny = true;
            }

            if (!didAny)
                ImGui.TextColored(ImGuiColors.DalamudGrey, "没有合集，请在“插件合集”中添加");

            ImGui.Separator();

            if (ImGuiComponents.IconButton(FontAwesomeIcon.Times))
            {
                this.enableDisableStatus          = OperationStatus.InProgress;
                this.enableDisableWorkingPluginId = plugin.EffectiveWorkingPluginId;
                var profiles = profileManager.Profiles
                                             .Where(profile => !profile.IsDefaultProfile && profile.WantsPlugin(plugin.EffectiveWorkingPluginId) != null)
                                             .ToArray();
                Task.Run
                (async () =>
                    {
                        await profileManager.DefaultProfile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, plugin.IsLoaded, false);
                        foreach (var profile in profiles)
                            await profile.RemoveAsync(plugin.EffectiveWorkingPluginId, false);
                        await profileManager.ApplyAllWantStatesAsync("从合集中移除");
                    }
                ).ContinueWith
                (task =>
                    {
                        this.enableDisableStatus = OperationStatus.Complete;
                        this.DisplayErrorContinuation(task, "处理合集失败\n请重启游戏并重试，如果此错误再次出现，请向开发团队反馈。");
                    }
                );
            }

            ImGui.SameLine();
            ImGui.Text("从所有合集中移除");

            ImGui.EndPopup();
        }

        var inMultipleProfiles = !isDefaultPlugin && !isInSingleProfile;
        var inSingleNonDefaultProfileWhichIsDisabled =
            isInSingleProfile && !profilesThatWantThisPlugin.First().IsEnabled;
        var inSingleNonDefaultProfileWhichDoesNotWantActive =
            isInSingleProfile && !profilesThatWantThisPlugin.First().CheckWantsActiveFromGameState(Service<PlayerState>.Get().ContentId);

        // Plugins in LoadError have a working toggle to allow for manual retries
        if (plugin.State is PluginState.UnloadError or PluginState.DependencyResolutionFailed && config.DevMode.GetValueOrDefault(false) && !plugin.IsOutdated)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, false);

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("插件加载或卸载失败，请重启游戏后重试");
        }
        else if (this.enableDisableStatus == OperationStatus.InProgress && this.enableDisableWorkingPluginId == plugin.EffectiveWorkingPluginId)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, this.loadingIndicatorKind == LoadingIndicatorKind.EnablingSingle);
        }
        else if (disabled                                        ||
                 inMultipleProfiles                              ||
                 inSingleNonDefaultProfileWhichIsDisabled        ||
                 inSingleNonDefaultProfileWhichDoesNotWantActive ||
                 pluginManager.SafeMode)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, isLoadedAndUnloadable);

            if (pluginManager.SafeMode && ImGui.IsItemHovered())
                ImGui.SetTooltip("安全模式下无法启用插件");
            else if (inMultipleProfiles && ImGui.IsItemHovered())
                ImGui.SetTooltip("此插件已加入多个合集，如需启用或禁用，请通过启用或禁用对应合集来操作\n如需在此处管理，请确保它只属于一个合集");
            else if (inSingleNonDefaultProfileWhichIsDisabled && ImGui.IsItemHovered())
                ImGui.SetTooltip($"包含此插件的合集“{profilesThatWantThisPlugin.First().Name}”已被禁用\n请在合集管理器中启用该合集，以单独切换此插件");
            else if (inSingleNonDefaultProfileWhichDoesNotWantActive && ImGui.IsItemHovered())
                ImGui.SetTooltip($"包含此插件的合集“{profilesThatWantThisPlugin.First().Name}”已激活，但未设置在当前角色上激活\n请修改该合集的设置，或将插件从该合集中移除，以单独切换此插件");
        }
        else
        {
            if (ImGuiComponents.ToggleButton(toggleId, ref isLoadedAndUnloadable))
            {
                var applicableProfile = profilesThatWantThisPlugin.First();
                Log.Verbose
                (
                    "Switching {InternalName} in {Profile} to {State}",
                    plugin.InternalName,
                    applicableProfile,
                    isLoadedAndUnloadable
                );

                try
                {
                    // Reload the devPlugin manifest if it's a dev plugin
                    // The plugin might rely on changed values in the manifest
                    if (plugin is LocalDevPlugin devPlugin)
                    {
                        devPlugin.ReloadManifest();
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Could not reload DevPlugin manifest");
                }

                // NOTE: We don't use the profile manager to actually handle loading/unloading here,
                // because that might cause us to show an error if a plugin we don't actually care about
                // fails to load/unload. Instead, we just do it ourselves and then update the profile.
                // There is probably a smarter way to handle this, but it's probably more code.
                if (!isLoadedAndUnloadable)
                {
                    this.enableDisableStatus          = OperationStatus.InProgress;
                    this.loadingIndicatorKind         = LoadingIndicatorKind.DisablingSingle;
                    this.enableDisableWorkingPluginId = plugin.EffectiveWorkingPluginId;

                    Task.Run
                    (async () =>
                        {
                            await plugin.UnloadAsync();
                            await applicableProfile.AddOrUpdateAsync
                            (
                                plugin.EffectiveWorkingPluginId,
                                plugin.Manifest.InternalName,
                                false,
                                false
                            );

                            notifications.AddNotification
                                ($"禁用了“{plugin.Manifest.Name}”。", "插件已禁用", NotificationType.Success);
                        }
                    ).ContinueWith
                    (t =>
                        {
                            this.enableDisableStatus = OperationStatus.Complete;
                            this.DisplayErrorContinuation(t, $"卸载插件 {plugin.Name} 失败\n请重启游戏并重试，如果此错误再次出现，请联系插件作者");
                        }
                    );
                }
                else
                {
                    _ = this.EnablePluginAsync(plugin, applicableProfile, availableUpdate);
                }
            }
        }

        // StyleModelV1.DalamudStandard.Pop();

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(15, 0);

        if (plugin.State == PluginState.Loaded)
        {
            // Only if the plugin isn't broken.
            DrawOpenPluginSettingsButton(plugin);

            ImGui.SameLine();
            ImGuiHelpers.ScaledDummy(5, 0);
        }

        if (config.ProfilesEnabled)
        {
            ImGui.SameLine();

            using (ImRaii.Disabled(!applicableForProfiles))
            {
                if (ImGuiComponents.IconButton(FontAwesomeIcon.Toolbox))
                    ImGui.OpenPopup(profileChooserPopupName);
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip
                (
                    applicableForProfiles ?
                        "为此插件选择合集" :
                        "此插件不支持合集"
                );
        }
    }

    private async Task EnablePluginAsync
    (
        LocalPlugin            plugin,
        Profile                profile,
        AvailablePluginUpdate? availableUpdate
    )
    {
        this.enableDisableStatus          = OperationStatus.InProgress;
        this.loadingIndicatorKind         = LoadingIndicatorKind.EnablingSingle;
        this.enableDisableWorkingPluginId = plugin.EffectiveWorkingPluginId;

        try
        {
            var pluginManager = Service<PluginManager>.Get();

            if (pluginManager.ReposReady             &&
                this.availablePluginsChanged == 0    &&
                availableUpdate              != null &&
                !plugin.IsDev)
            {
                if (await this.ShowUpdateModal(plugin))
                {
                    await profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false);
                    await this.UpdateSinglePlugin(availableUpdate);
                    return;
                }
            }

            await profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false);
            await plugin.LoadAsync(PluginLoadReason.Installer);
            Service<NotificationManager>.Get().AddNotification($"已启用插件“{plugin.Manifest.Name}”。", "插件已启用", NotificationType.Success);
        }
        catch (OperationCanceledException)
        {
            // ignored
        }
        catch (Exception exception)
        {
            Log.Error(exception, "启用插件 {InternalName} 失败", plugin.InternalName);
            _ = this.ShowErrorModal($"启用插件“{plugin.Name}”失败，请查看日志。");
        }
        finally
        {
            this.enableDisableStatus = OperationStatus.Complete;
        }
    }

    private static string GetUpdateStatusText
    (
        PluginUpdateStatus.StatusKind status
    ) => status switch
    {
        PluginUpdateStatus.StatusKind.Pending         => "等待更新",
        PluginUpdateStatus.StatusKind.FailedDownload  => "下载失败",
        PluginUpdateStatus.StatusKind.FailedUnload    => "卸载失败",
        PluginUpdateStatus.StatusKind.FailedLoad      => "加载失败",
        PluginUpdateStatus.StatusKind.AlreadyUpToDate => "已是最新版本",
        PluginUpdateStatus.StatusKind.Success         => "更新成功",
        _                                             => "未知状态"
    };

    private async Task<bool> UpdateSinglePlugin
    (
        AvailablePluginUpdate update
    )
    {
        var pluginManager = Service<PluginManager>.Get();

        this.installStatus        = OperationStatus.InProgress;
        this.loadingIndicatorKind = LoadingIndicatorKind.UpdatingSingle;

        return await Task.Run
                         (async () =>
                             {
                                 await pluginManager.WaitForReposAsync();
                                 var currentUpdate = pluginManager.UpdatablePlugins.FirstOrDefault
                                                         (candidate => candidate.InstalledPlugin == update.InstalledPlugin) ??
                                                     throw new InvalidOperationException("刷新后已找不到此更新，请重新选择。");
                                 return await pluginManager.UpdateSinglePluginAsync(currentUpdate, true, false);
                             }
                         )
                         .ContinueWith
                         (task =>
                             {
                                 // There is no need to set as Complete for an individual plugin installation
                                 this.installStatus = OperationStatus.Idle;

                                 if (task.IsCompletedSuccessfully &&
                                     task.Result.Status != PluginUpdateStatus.StatusKind.Success)
                                 {
                                     this.ShowErrorModal
                                     (
                                         $"更新插件 {update.UpdateManifest.Name} 失败（{GetUpdateStatusText(task.Result.Status)}）\n请重启游戏并重试，如果此错误再次出现，请联系插件作者"
                                     );
                                     return false;
                                 }

                                 return this.DisplayErrorContinuation(task, $"更新插件 {update.UpdateManifest.Name} 失败（异常）\n请重启游戏并重试，如果此错误再次出现，请联系插件作者");
                             }
                         );
    }

    private void DrawUpdateSinglePluginButton
    (
        AvailablePluginUpdate update
    )
    {
        var       waitingForRefresh = !Service<PluginManager>.Get().ReposReady || this.availablePluginsChanged != 0;
        using var disabled          = ImRaii.Disabled(waitingForRefresh || this.AnyOperationInProgress);

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Download))
        {
            _ = this.UpdateSinglePlugin(update);
        }

        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
        {
            var updateVersion = update.UseTesting ?
                                    update.UpdateManifest.TestingAssemblyVersion :
                                    update.UpdateManifest.AssemblyVersion;
            ImGui.SetTooltip
            (
                waitingForRefresh ?
                    "等待插件列表刷新完成后更新" :
                    $"更新至 {updateVersion.ToString()}"
            );
        }
    }

    private static void DrawOpenPluginSettingsButton
    (
        LocalPlugin plugin
    )
    {
        var hasMainUi = plugin.DalamudInterface?.LocalUiBuilder.HasMainUi   ?? false;
        var hasConfig = plugin.DalamudInterface?.LocalUiBuilder.HasConfigUi ?? false;

        if (hasMainUi)
        {
            ImGui.SameLine();

            if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.ArrowUpRightFromSquare, "打开"))
            {
                try
                {
                    plugin.DalamudInterface.LocalUiBuilder.OpenMain();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "打开“{PluginName}”的主界面失败。", plugin.Name);
                }
            }

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip("打开此插件的界面");
            }
        }

        if (hasConfig)
        {
            if (hasMainUi)
            {
                ImGui.SameLine();
                ImGuiHelpers.ScaledDummy(5, 0);
            }

            ImGui.SameLine();

            if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Cog, "设置"))
            {
                try
                {
                    plugin.DalamudInterface.LocalUiBuilder.OpenConfig();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "打开“{PluginName}”的配置界面失败。", plugin.Name);
                }
            }

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip("打开此插件的设置");
            }
        }
    }

    private void DrawSendFeedbackButton
    (
        RemotePluginManifest manifest,
        bool                 isTesting,
        bool                 big
    )
    {
        var clicked = big ?
                          ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Comment, "发送反馈") :
                          ImGuiComponents.IconButton(FontAwesomeIcon.Comment);

        if (clicked)
        {
            this.feedbackPlugin           = manifest;
            this.feedbackModalOnNextFrame = true;
            this.feedbackIsTesting        = isTesting;
        }

        if (ImGui.IsItemHovered())
        {
            ImGui.SetTooltip("发送反馈");
        }
    }

    private void DrawDeletePluginButton
    (
        LocalPlugin plugin
    )
    {
        var pluginManager = Service<PluginManager>.Get();

        ImGui.SameLine();

        if (plugin.State == PluginState.Loaded)
        {
            ImGui.PushFont(InterfaceManager.IconFont);
            ImGuiComponents.DisabledButton(FontAwesomeIcon.TrashAlt.ToIconString());
            ImGui.PopFont();

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip
                (
                    plugin.State == PluginState.Loaded ?
                        "请先禁用此插件再删除" :
                        "当前无法删除——请重启游戏"
                );
            }
        }
        else
        {
            if (ImGuiComponents.IconButton(FontAwesomeIcon.TrashAlt))
            {
                try
                {
                    if (plugin.IsDev)
                    {
                        plugin.DllFile.Delete();
                    }
                    else
                    {
                        plugin.ScheduleDeletion(!plugin.Manifest.ScheduledForDeletion);
                    }

                    if (plugin.State is PluginState.Unloaded or PluginState.DependencyResolutionFailed)
                    {
                        pluginManager.RemovePlugin(plugin);

                        this.openPluginCollapsibles.Remove($"installed:{plugin.EffectiveWorkingPluginId}");
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Plugin installer threw an error during removal of {PluginName}", plugin.Name);

                    this.ShowErrorModal($"删除插件 {plugin.Name} 失败\n请重启游戏并重试，如果此错误再次出现，请联系插件作者");
                }
            }

            if (ImGui.IsItemHovered())
            {
                string tooltipMessage;

                if (plugin.Manifest.ScheduledForDeletion)
                {
                    tooltipMessage = "取消计划删除";
                }
                else if (plugin.State is PluginState.Unloaded or PluginState.DependencyResolutionFailed)
                {
                    tooltipMessage = "删除插件";
                }
                else
                {
                    tooltipMessage = "在下次重启时删除插件";
                }

                ImGui.SetTooltip(tooltipMessage);
            }
        }
    }
}
