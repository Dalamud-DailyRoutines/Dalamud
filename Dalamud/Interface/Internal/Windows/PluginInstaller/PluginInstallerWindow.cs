using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using CheapLoc;

using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Console;
using Dalamud.Game.Command;
using Dalamud.Game.Player;
using Dalamud.Interface.Animation.EasingFunctions;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Textures.Internal;
using Dalamud.Interface.Textures.TextureWraps;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Interface.Windowing;
using Dalamud.Logging.Internal;
using Dalamud.Plugin;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Exceptions;
using Dalamud.Plugin.Internal.Profiles;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;
using Dalamud.Support;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// Class responsible for drawing the plugin installer.
/// </summary>
internal class PluginInstallerWindow : Window, IDisposable
{
    private static readonly ModuleLog Log = ModuleLog.Create<PluginInstallerWindow>();

    private readonly Vector4 changelogBgColor   = new(0.114f, 0.584f, 0.192f, 0.678f);
    private readonly Vector4 changelogTextColor = new(0.812f, 1.000f, 0.816f, 1.000f);

    private readonly PluginImageCache      imageCache;
    private readonly PluginCategoryManager categoryManager = new();

    private readonly List<int> openPluginCollapsibles = [];

    private readonly DateTime timeLoaded;

    private readonly object listLock = new();

    private readonly ProfileManagerWidget profileManagerWidget;

    private readonly Stopwatch tooltipFadeInStopwatch = new();

    private readonly InOutCubic tooltipFadeEasing = new(TimeSpan.FromSeconds(0.2f))
    {
        Point1 = Vector2.Zero,
        Point2 = Vector2.One
    };

    private DalamudChangelogManager? dalamudChangelogManager;
    private Task?                    dalamudChangelogRefreshTask;
    private CancellationTokenSource? dalamudChangelogRefreshTaskCts;

    #region Image Tester State

    private readonly string[] testerImagePaths = new string[5];
    private          string   testerIconPath   = string.Empty;

    private Task<IDalamudTextureWrap>?[]? testerImages;
    private Task<IDalamudTextureWrap>?    testerIcon;

    private bool testerError;
    private bool testerUpdateAvailable;

    #endregion

    private bool                  errorModalDrawing = true;
    private bool                  errorModalOnNextFrame;
    private string                errorModalMessage = string.Empty;
    private TaskCompletionSource? errorModalTaskCompletionSource;

    private bool                        updateModalDrawing = true;
    private bool                        updateModalOnNextFrame;
    private LocalPlugin?                updateModalPlugin;
    private TaskCompletionSource<bool>? updateModalTaskCompletionSource;

    private bool testingWarningModalDrawing = true;
    private bool testingWarningModalOnNextFrame;

    private bool                        deletePluginConfigWarningModalDrawing = true;
    private bool                        deletePluginConfigWarningModalOnNextFrame;
    private bool                        deletePluginConfigWarningModalExplainTesting;
    private string                      deletePluginConfigWarningModalPluginName = string.Empty;
    private TaskCompletionSource<bool>? deletePluginConfigWarningModalTaskCompletionSource;

    private bool feedbackModalDrawing = true;
    private bool feedbackModalOnNextFrame = false;
    private bool feedbackModalOnNextFrameDontClear = false;
    private string feedbackModalBody = string.Empty;
    private string feedbackModalContact = string.Empty;
    private bool feedbackModalIncludeException = false;
    private RemotePluginManifest? feedbackPlugin = null;
    private bool feedbackIsTesting = false;

    private int                       updatePluginCount;
    private List<PluginUpdateStatus>? updatedPlugins;

    [SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1201:Elements should appear in the correct order", Justification = "Makes sense like this")]
    private List<RemotePluginManifest> pluginListAvailable = [];
    private List<LocalPlugin> pluginListInstalled = [];
    private List<AvailablePluginUpdate> pluginListUpdatable = [];
    private bool hasDevPlugins = false;
    private bool hasHiddenPlugins = false;

    private string searchText = string.Empty;
    private bool   isSearchTextPrefilled;

    private PluginSortKind sortKind     = PluginSortKind.Alphabetical;
    private string         filterText   = Locs.SortBy_Alphabetical;
    private bool           adaptiveSort = true;

    private OperationStatus installStatus = OperationStatus.Idle;
    private OperationStatus updateStatus  = OperationStatus.Idle;

    private OperationStatus enableDisableStatus          = OperationStatus.Idle;
    private Guid            enableDisableWorkingPluginId = Guid.Empty;

    private LoadingIndicatorKind loadingIndicatorKind = LoadingIndicatorKind.Unknown;

    private string verifiedCheckmarkHoveredPlugin = string.Empty;

    private string? staleDalamudNewVersion;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstallerWindow"/> class.
    /// </summary>
    /// <param name="imageCache">An instance of <see cref="PluginImageCache"/> class.</param>
    /// <param name="configuration">An instance of <see cref="DalamudConfiguration"/>.</param>
    public PluginInstallerWindow(PluginImageCache imageCache, DalamudConfiguration configuration)
        : base("插件安装器###XlPluginInstaller", ImGuiWindowFlags.NoScrollbar)
    {
        this.pluginListInstalled = [];
        this.IsOpen              = true;
        this.imageCache          = imageCache;

        this.Size = new Vector2(830, 570);
        this.SizeCondition = ImGuiCond.FirstUseEver;

        this.SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = this.Size.Value,
        };
        
        Service<PluginManager>.GetAsync().ContinueWith(pluginManagerTask =>
        {
            var pluginManager = pluginManagerTask.Result;

            // For debugging
            if (pluginManager.PluginsReady)
                this.OnInstalledPluginsChanged();

            this.dalamudChangelogManager = new(pluginManager);

            pluginManager.OnAvailablePluginsChanged += this.OnAvailablePluginsChanged;
            pluginManager.OnInstalledPluginsChanged += this.OnInstalledPluginsChanged;

            for (var i = 0; i < this.testerImagePaths.Length; i++)
            {
                this.testerImagePaths[i] = string.Empty;
            }
        });

        this.timeLoaded = DateTime.Now;

        this.profileManagerWidget = new(this);
    }

    private enum OperationStatus
    {
        Idle,
        InProgress,
        Complete,
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
        ProfilesLoading,
    }

    private enum PluginSortKind
    {
        Alphabetical,
        DownloadCount,
        LastUpdate,
        NewOrNot,
        NotInstalled,
        EnabledDisabled,
        ProfileOrNot,
        SearchScore,
    }

    [Flags]
    private enum PluginHeaderFlags
    {
        None = 0,
        IsThirdParty = 1 << 0,
        HasTrouble = 1 << 1,
        UpdateAvailable = 1 << 2,
        MainRepoCrossUpdate = 1 << 3,
        IsNew = 1 << 4,
        IsInstallableOutdated = 1 << 5,
        IsOrphan = 1 << 6,
        IsTesting = 1 << 7,
        IsIncompatible = 1 << 8,
    }

    private enum InstalledPluginListFilter
    {
        None,
        Testing,
        Updateable,
        Dev,
        Enabled,
        Disabled,
        Incompatible,
    }

    private bool AnyOperationInProgress => this.installStatus == OperationStatus.InProgress ||
                                           this.updateStatus == OperationStatus.InProgress ||
                                           this.enableDisableStatus == OperationStatus.InProgress;

    /// <inheritdoc/>
    public void Dispose()
    {
        this.dalamudChangelogRefreshTaskCts?.Cancel();

        var pluginManager = Service<PluginManager>.GetNullable();
        if (pluginManager != null)
        {
            pluginManager.OnAvailablePluginsChanged -= this.OnAvailablePluginsChanged;
            pluginManager.OnInstalledPluginsChanged -= this.OnInstalledPluginsChanged;
        }
    }

    /// <summary>
    /// Open to the installer to the page specified by <paramref name="kind"/>.
    /// </summary>
    /// <param name="kind">The page of the installer to open.</param>
    public void OpenTo(PluginInstallerOpenKind kind)
    {
        this.IsOpen = true;
        this.SetOpenPage(kind);
    }

    /// <summary>
    /// Toggle to the installer to the page specified by <paramref name="kind"/>.
    /// </summary>
    /// <param name="kind">The page of the installer to open.</param>
    public void ToggleTo(PluginInstallerOpenKind kind)
    {
        this.Toggle();

        if (this.IsOpen)
            this.SetOpenPage(kind);
    }

    /// <inheritdoc/>
    public override void OnOpen()
    {
        var pluginManager = Service<PluginManager>.Get();

        _ = pluginManager.ReloadAllReposAsync();
        _ = pluginManager.ScanDevPluginsAsync();

        if (!this.isSearchTextPrefilled)
        {
            this.searchText = string.Empty;
            this.sortKind = PluginSortKind.Alphabetical;
            this.filterText = Locs.SortBy_Alphabetical;
        }

        this.adaptiveSort = true;

        if (this.updateStatus is OperationStatus.Complete or OperationStatus.Idle)
        {
            this.updateStatus = OperationStatus.Idle;
            this.updatePluginCount = 0;
            this.updatedPlugins = null;
        }

        this.profileManagerWidget.Reset();

        if (this.staleDalamudNewVersion == null && !Versioning.GetActiveTrack().IsNullOrEmpty())
        {
            Service<DalamudReleases>.Get().GetVersionForCurrentTrack().ContinueWith(t =>
            {
                if (!t.IsCompletedSuccessfully)
                    return;

                var versionInfo = t.Result;
                if (versionInfo.AssemblyVersion != Versioning.GetScmVersion())
                {
                    this.staleDalamudNewVersion = versionInfo.AssemblyVersion;
                }
            });
        }
    }

    /// <inheritdoc/>
    public override void OnClose()
    {
        Service<DalamudConfiguration>.Get().QueueSave();

        if (this.isSearchTextPrefilled)
        {
            this.isSearchTextPrefilled = false;
            this.searchText = string.Empty;
        }
    }

    /// <inheritdoc/>
    public override void Draw()
    {
        lock (this.listLock)
        {
            this.DrawHeader();
            this.DrawPluginCategories();
            this.DrawFooter();
            this.DrawErrorModal();
            this.DrawUpdateModal();
            this.DrawTestingWarningModal();
            this.DrawDeletePluginConfigWarningModal();
            this.DrawFeedbackModal();
            this.DrawProgressOverlay();
        }
    }

    /// <summary>
    /// Clear the icon and image caches, forcing a fresh download.
    /// </summary>
    public void ClearIconCache()
    {
        this.imageCache.ClearIconCache();
    }

    /// <summary>
    /// Sets the current search text and marks it as prefilled.
    /// </summary>
    /// <param name="text">The search term.</param>
    public void SetSearchText(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            this.isSearchTextPrefilled = false;
            this.searchText = string.Empty;
            if (this.sortKind == PluginSortKind.SearchScore)
            {
                this.sortKind = PluginSortKind.Alphabetical;
                this.filterText = Locs.SortBy_Alphabetical;
                this.ResortPlugins();
            }
        }
        else
        {
            this.isSearchTextPrefilled = true;
            this.searchText = text;
            this.sortKind = PluginSortKind.SearchScore;
            this.filterText = Locs.SortBy_SearchScore;
            this.ResortPlugins();
        }
    }

    /// <summary>
    /// Start a plugin install and handle errors visually.
    /// </summary>
    /// <param name="manifest">The manifest to install.</param>
    /// <param name="useTesting">Install the testing version.</param>
    public void StartInstall(RemotePluginManifest manifest, bool useTesting)
    {
        var pluginManager = Service<PluginManager>.Get();
        var notifications = Service<NotificationManager>.Get();

        this.installStatus = OperationStatus.InProgress;
        this.loadingIndicatorKind = LoadingIndicatorKind.Installing;

        Task.Run(() => pluginManager.InstallPluginAsync(manifest, useTesting || manifest.IsTestingExclusive, PluginLoadReason.Installer))
            .ContinueWith(task =>
            {
                // There is no need to set as Complete for an individual plugin installation
                this.installStatus = OperationStatus.Idle;
                if (this.DisplayErrorContinuation(task, Locs.ErrorModal_InstallFail(manifest.Name)))
                {
                    // Fine as long as we aren't in an error state
                    if (task.Result.State is PluginState.Loaded or PluginState.Unloaded)
                    {
                        notifications.AddNotification(Locs.Notifications_PluginInstalled(manifest.Name), Locs.Notifications_PluginInstalledTitle, NotificationType.Success);
                    }
                    else
                    {
                        notifications.AddNotification(Locs.Notifications_PluginNotInstalled(manifest.Name), Locs.Notifications_PluginNotInstalledTitle, NotificationType.Error);
                        this.ShowErrorModal(Locs.ErrorModal_InstallFail(manifest.Name));
                    }
                }
            });
    }

    /// <summary>
    /// A continuation task that displays any errors received into the error modal.
    /// </summary>
    /// <param name="task">The previous task.</param>
    /// <param name="state">An error message to be displayed.</param>
    /// <returns>A value indicating whether to continue with the next task.</returns>
    public bool DisplayErrorContinuation(Task task, object state)
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

        this.ShowErrorModal(newErrorMessage ?? "An unknown error occurred.");

        return false;
    }

    private static void EnsureHaveTestingOptIn(IPluginManifest manifest)
    {
        var configuration = Service<DalamudConfiguration>.Get();

        if (configuration.PluginTestingOptIns.Any(x => x.InternalName == manifest.InternalName))
            return;

        configuration.PluginTestingOptIns.Add(new PluginTestingOptIn(manifest.InternalName));
        configuration.QueueSave();
    }

    private static void DrawProgressBar<T>(IEnumerable<T> items, Func<T, bool> pendingFunc, Func<T, bool> totalFunc, Action<T> renderPending)
    {
        var windowSize = ImGui.GetWindowSize();

        var numLoaded = 0;
        var total = 0;

        var itemsArray = items as T[] ?? items.ToArray();
        var allPending = itemsArray.Where(pendingFunc)
                                   .ToArray();
        var allLoadedOrLoading = itemsArray.Count(totalFunc);

        // Cap number of items we show to avoid clutter
        const int maxShown = 3;
        foreach (var repo in allPending.Take(maxShown))
        {
            renderPending(repo);
        }

        ImGuiHelpers.ScaledDummy(10);

        numLoaded += allLoadedOrLoading - allPending.Length;
        total += allLoadedOrLoading;
        if (numLoaded != total)
        {
            ImGui.SetCursorPosX(windowSize.X / 3);
            ImGui.ProgressBar(numLoaded / (float)total, new Vector2(windowSize.X / 3, 50), $"{numLoaded}/{total}");
        }
    }

    private void SetOpenPage(PluginInstallerOpenKind kind)
    {
        switch (kind)
        {
            case PluginInstallerOpenKind.AllPlugins:
                // Plugins group
                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Available;
                // All category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.InstalledPlugins:
                // Installed group
                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Installed;
                // All category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.UpdateablePlugins:
                // Installed group
                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Installed;
                // Updateable category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.UpdateablePlugins;
                break;
            case PluginInstallerOpenKind.Changelogs:
                // Changelog group
                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Changelog;
                // Plugins category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.DalamudChangelogs:
                // Changelog group
                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Changelog;
                // Dalamud category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.DalamudChangelogs;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, null);
        }
    }

    private void DrawProgressOverlay()
    {
        var pluginManager = Service<PluginManager>.Get();
        var profileManager = Service<ProfileManager>.Get();

        var isWaitingManager = !pluginManager.PluginsReady ||
                               !pluginManager.ReposReady;
        var isWaitingProfiles = profileManager.IsBusy;

        var isLoading = this.AnyOperationInProgress ||
                        isWaitingManager || isWaitingProfiles;

        if (isWaitingManager)
            this.loadingIndicatorKind = LoadingIndicatorKind.Manager;
        else if (isWaitingProfiles)
            this.loadingIndicatorKind = LoadingIndicatorKind.ProfilesLoading;

        if (!isLoading)
            return;

        ImGui.SetCursorPos(Vector2.Zero);

        var windowSize = ImGui.GetWindowSize();
        var titleHeight = ImGui.GetFontSize() + (ImGui.GetStyle().FramePadding.Y * 2);

        using var loadingChild = ImRaii.Child("###installerLoadingFrame"u8, new Vector2(-1, -1), false);
        if (loadingChild)
        {
            ImGui.GetWindowDrawList().PushClipRectFullScreen();
            ImGui.GetWindowDrawList().AddRectFilled(
                ImGui.GetWindowPos() + new Vector2(0, titleHeight),
                ImGui.GetWindowPos() + windowSize,
                ImGui.ColorConvertFloat4ToU32(new(0f, 0f, 0f, 0.8f * ImGui.GetStyle().Alpha)),
                ImGui.GetStyle().WindowRounding,
                ImDrawFlags.RoundCornersBottom);
            ImGui.PopClipRect();

            ImGui.SetCursorPosY(windowSize.Y / 2);

            switch (this.loadingIndicatorKind)
            {
                case LoadingIndicatorKind.Unknown:
                    ImGuiHelpers.CenteredText("总之在干点什么, 但不知道在干什么");
                    break;
                case LoadingIndicatorKind.EnablingSingle:
                    ImGuiHelpers.CenteredText("启用插件中...");
                    break;
                case LoadingIndicatorKind.DisablingSingle:
                    ImGuiHelpers.CenteredText("禁用插件中...");
                    break;
                case LoadingIndicatorKind.UpdatingSingle:
                    ImGuiHelpers.CenteredText("更新插件中...");
                    break;
                case LoadingIndicatorKind.UpdatingAll:
                    ImGuiHelpers.CenteredText("批量更新插件中...");
                    break;
                case LoadingIndicatorKind.Installing:
                    ImGuiHelpers.CenteredText("安装插件中...");
                    break;
                case LoadingIndicatorKind.Manager:
                    {
                        if (pluginManager.PluginsReady && !pluginManager.ReposReady)
                        {
                            ImGuiHelpers.CenteredText("加载插件仓库中...");
                            ImGuiHelpers.ScaledDummy(10);

                            DrawProgressBar(pluginManager.Repos, x => x.State != PluginRepositoryState.Success &&
                                                                      x.State != PluginRepositoryState.Fail &&
                                                                      x.IsEnabled,
                                            x => x.IsEnabled,
                                            x => ImGuiHelpers.CenteredText($"正在加载 {x.PluginMasterUrl}"));
                        }
                        else if (!pluginManager.PluginsReady && pluginManager.ReposReady)
                        {
                            ImGuiHelpers.CenteredText("加载已安装插件中...");
                            ImGuiHelpers.ScaledDummy(10);

                            DrawProgressBar(pluginManager.InstalledPlugins, x => x.State == PluginState.Loading,
                                            x => x.State is PluginState.Loaded or
                                                     PluginState.LoadError or
                                                     PluginState.Loading,
                                            x => ImGuiHelpers.CenteredText($"正在加载 {x.Name}"));
                        }
                        else
                        {
                            ImGuiHelpers.CenteredText("加载插件仓库与插件信息中...");
                        }
                    }

                    break;
                case LoadingIndicatorKind.ProfilesLoading:
                    ImGuiHelpers.CenteredText("应用合集中...");
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            if (DateTime.Now - this.timeLoaded > TimeSpan.FromSeconds(30) && !pluginManager.PluginsReady)
            {
                ImGuiHelpers.ScaledDummy(10);
                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.AttentionForeground);
                ImGuiHelpers.CenteredText("任一插件正在阻碍插件安装器加载, 请自行检查\n然后使用安全模式重启, 并删除相关插件");
                ImGui.PopStyleColor();

                ImGuiHelpers.BeginHorizontalButtonGroup()
                            .Add(
                                "Restart in Safe Mode",
                                () =>
                                {
                                    var config = Service<DalamudConfiguration>.Get();
                                    config.PluginSafeMode = true;
                                    config.ForceSave();
                                    Dalamud.RestartGame();
                                })
                            .SetCentered(true)
                            .WithHeight(30)
                            .Draw();
            }
        }
    }

    private void DrawHeader()
    {
        var style = ImGui.GetStyle();

        ImGui.SetCursorPosY(ImGui.GetCursorPosY() - (5 * ImGuiHelpers.GlobalScale));

        var searchClearButtonWidth = 25 * ImGuiHelpers.GlobalScale;

        var sortSelectables = new (string Localization, PluginSortKind SortKind)[]
        {
            (Locs.SortBy_SearchScore, PluginSortKind.SearchScore),
            (Locs.SortBy_Alphabetical, PluginSortKind.Alphabetical),
            (Locs.SortBy_DownloadCounts, PluginSortKind.DownloadCount),
            (Locs.SortBy_LastUpdate, PluginSortKind.LastUpdate),
            (Locs.SortBy_NewOrNot, PluginSortKind.NewOrNot),
            (Locs.SortBy_NotInstalled, PluginSortKind.NotInstalled),
            (Locs.SortBy_EnabledDisabled, PluginSortKind.EnabledDisabled),
            (Locs.SortBy_ProfileOrNot, PluginSortKind.ProfileOrNot),
        };
        var longestSelectableWidth = sortSelectables.Select(t => ImGui.CalcTextSize(t.Localization).X).Max();
        var selectableWidth = longestSelectableWidth + (style.FramePadding.X * 2);  // This does not include the label

        var isProfileManager =
            this.categoryManager.CurrentGroupKind == PluginCategoryManager.GroupKind.Installed &&
            this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.PluginProfiles;

        // Disable search if profile editor
        using (ImRaii.Disabled(isProfileManager))
        {
            var searchTextChanged = false;
            var prevSearchText = this.searchText;
            ImGui.SameLine();
            ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X - selectableWidth - searchClearButtonWidth);
            searchTextChanged |= ImGui.InputTextWithHint(
                "###XlPluginInstaller_Search"u8,
                Locs.Header_SearchPlaceholder,
                ref this.searchText,
                100,
                ImGuiInputTextFlags.AutoSelectAll);

            ImGui.SameLine();
            ImGui.SetNextItemWidth(searchClearButtonWidth);
            if (ImGuiComponents.IconButton(FontAwesomeIcon.Times))
            {
                this.searchText = string.Empty;
                searchTextChanged = true;
            }

            if (searchTextChanged)
            {
                if (this.adaptiveSort)
                {
                    if (string.IsNullOrWhiteSpace(this.searchText))
                    {
                        this.sortKind = PluginSortKind.Alphabetical;
                        this.filterText = Locs.SortBy_Alphabetical;
                    }
                    else
                    {
                        this.sortKind = PluginSortKind.SearchScore;
                        this.filterText = Locs.SortBy_SearchScore;
                    }

                    this.ResortPlugins();
                }
                else if (this.sortKind == PluginSortKind.SearchScore)
                {
                    this.ResortPlugins();
                }

                this.UpdateCategoriesOnSearchChange(prevSearchText);
            }
        }

        // Disable sort if changelogs or profile editor
        using (ImRaii.Disabled(this.categoryManager.CurrentGroupKind == PluginCategoryManager.GroupKind.Changelog || isProfileManager))
        {
            ImGui.SameLine();
            ImGui.SetNextItemWidth(selectableWidth);
            if (ImGui.BeginCombo("###SortBy", this.filterText, ImGuiComboFlags.NoArrowButton))
            {
                foreach (var selectable in sortSelectables)
                {
                    if (selectable.SortKind == PluginSortKind.SearchScore && string.IsNullOrWhiteSpace(this.searchText))
                        continue;

                    if (ImGui.Selectable(selectable.Localization))
                    {
                        this.sortKind = selectable.SortKind;
                        this.filterText = selectable.Localization;
                        this.adaptiveSort = false;

                        lock (this.listLock)
                        {
                            this.ResortPlugins();
                            this.openPluginCollapsibles.Clear();
                        }
                    }
                }

                ImGui.EndCombo();
            }
        }
    }

    private void DrawFooter()
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var windowSize = ImGui.GetWindowContentRegionMax();
        var placeholderButtonSize = ImGuiHelpers.GetButtonSize("placeholder");

        ImGui.Separator();

        ImGui.SetCursorPosY(windowSize.Y - placeholderButtonSize.Y);

        this.DrawUpdatePluginsButton();
        
        ImGui.SameLine();
        if (ImGui.Button("扫描开发版插件"))
            _ = pluginManager.ScanDevPluginsAsync();
        
        ImGui.SameLine();
        if (ImGui.Button("刷新插件列表"))
            _ = pluginManager.ReloadAllReposAsync();
        
        ImGui.SameLine();
        ImGui.TextDisabled("|");

        ImGui.SameLine();
        if (ImGui.Button(Locs.FooterButton_Settings))
            Service<DalamudInterface>.Get().OpenSettings();

        var closeText = Locs.FooterButton_Close;
        var closeButtonSize = ImGuiHelpers.GetButtonSize(closeText);

        ImGui.SameLine(windowSize.X - closeButtonSize.X - 20);
        if (ImGui.Button(closeText))
        {
            this.IsOpen = false;
            configuration.QueueSave();
        }
    }

    private void DrawUpdatePluginsButton()
    {
        var pluginManager = Service<PluginManager>.Get();
        var notifications = Service<NotificationManager>.Get();

        var ready = pluginManager.PluginsReady && pluginManager.ReposReady;

        if (pluginManager.SafeMode)
        {
            ImGuiComponents.DisabledButton(Locs.FooterButton_UpdateSafeMode);
        }
        else if (!ready || this.updateStatus == OperationStatus.InProgress || this.installStatus == OperationStatus.InProgress)
        {
            ImGuiComponents.DisabledButton(Locs.FooterButton_UpdatePlugins);
        }
        else if (this.updateStatus == OperationStatus.Complete)
        {
            ImGui.Button(this.updatePluginCount > 0
                             ? Locs.FooterButton_UpdateComplete(this.updatePluginCount)
                             : Locs.FooterButton_NoUpdates);
        }
        else
        {
            if (ImGui.Button(Locs.FooterButton_UpdatePlugins))
            {
                this.updateStatus = OperationStatus.InProgress;
                this.loadingIndicatorKind = LoadingIndicatorKind.UpdatingAll;

                var toUpdate = this.pluginListUpdatable
                                   .Where(x => x.InstalledPlugin.IsWantedByAnyProfile)
                                   .ToList();

                Task.Run(() => pluginManager.UpdatePluginsAsync(toUpdate, false))
                    .ContinueWith(task =>
                    {
                        this.updateStatus = OperationStatus.Complete;

                        if (task.IsFaulted)
                        {
                            this.updatePluginCount = 0;
                            this.updatedPlugins = null;
                            this.DisplayErrorContinuation(task, Locs.ErrorModal_UpdaterFatal);
                        }
                        else
                        {
                            this.updatedPlugins = task.Result.Where(res => res.Status == PluginUpdateStatus.StatusKind.Success).ToList();
                            this.updatePluginCount = this.updatedPlugins.Count;

                            var errorPlugins = task.Result.Where(res => res.Status != PluginUpdateStatus.StatusKind.Success).ToList();
                            var errorPluginCount = errorPlugins.Count;

                            if (errorPluginCount > 0)
                            {
                                var errorMessage = this.updatePluginCount > 0
                                                       ? Locs.ErrorModal_UpdaterFailPartial(this.updatePluginCount, errorPluginCount)
                                                       : Locs.ErrorModal_UpdaterFail(errorPluginCount);

                                var hintInsert = errorPlugins
                                                 .Aggregate(string.Empty, (current, pluginUpdateStatus) => $"{current}* {pluginUpdateStatus.InternalName} ({PluginUpdateStatus.LocalizeUpdateStatusKind(pluginUpdateStatus.Status)})\n")
                                                 .TrimEnd();
                                errorMessage += Locs.ErrorModal_HintBlame(hintInsert);

                                this.DisplayErrorContinuation(task, errorMessage);
                            }

                            if (this.updatePluginCount > 0)
                            {
                                Service<PluginManager>.Get().PrintUpdatedPlugins(this.updatedPlugins, Locs.PluginUpdateHeader_Chatbox);
                                notifications.AddNotification(new Notification
                                {
                                    Title = Locs.Notifications_UpdatesInstalledTitle,
                                    Content = Locs.Notifications_UpdatesInstalled(this.updatedPlugins),
                                    Type = NotificationType.Success,
                                    Icon = INotificationIcon.From(FontAwesomeIcon.Download),
                                });

                                this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Installed;
                            }
                            else if (this.updatePluginCount == 0)
                            {
                                notifications.AddNotification(Locs.Notifications_NoUpdatesFound, Locs.Notifications_NoUpdatesFoundTitle, NotificationType.Info);
                            }
                        }
                    });
            }
        }
    }

    private void DrawErrorModal()
    {
        var modalTitle = Locs.ErrorModal_Title;

        if (ImGui.BeginPopupModal(modalTitle, ref this.errorModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text(this.errorModalMessage);
            ImGui.Spacing();

            var buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - buttonWidth) / 2);

            if (ImGui.Button(Locs.ErrorModalButton_Ok, new Vector2(buttonWidth, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.errorModalTaskCompletionSource?.SetResult();
            }

            ImGui.EndPopup();
        }

        if (this.errorModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(modalTitle);
            this.errorModalOnNextFrame = false;
            this.errorModalDrawing = true;
        }
    }

    private void DrawUpdateModal()
    {
        var modalTitle = Locs.UpdateModal_Title;

        if (this.updateModalPlugin == null)
            return;

        if (ImGui.BeginPopupModal(modalTitle, ref this.updateModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text(Locs.UpdateModal_UpdateAvailable(this.updateModalPlugin.Name));
            ImGui.Spacing();

            var buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ((buttonWidth * 2) - (ImGui.GetStyle().ItemSpacing.Y * 2))) / 2);

            if (ImGui.Button(Locs.UpdateModal_Yes, new Vector2(buttonWidth, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.updateModalTaskCompletionSource?.SetResult(true);
            }

            ImGui.SameLine();

            if (ImGui.Button(Locs.UpdateModal_No, new Vector2(buttonWidth, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.updateModalTaskCompletionSource?.SetResult(false);
            }

            ImGui.EndPopup();
        }

        if (this.updateModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(modalTitle);
            this.updateModalOnNextFrame = false;
            this.updateModalDrawing = true;
        }
    }

    private void DrawTestingWarningModal()
    {
        var modalTitle = Locs.TestingWarningModal_Title;

        if (ImGui.BeginPopupModal(modalTitle, ref this.testingWarningModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text(Locs.TestingWarningModal_DowngradeBody);

            ImGuiHelpers.ScaledDummy(10);

            var buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - buttonWidth) / 2);

            if (ImGui.Button(Locs.ErrorModalButton_Ok, new Vector2(buttonWidth, 40)))
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

            ImGui.OpenPopup(modalTitle);
            this.testingWarningModalOnNextFrame = false;
            this.testingWarningModalDrawing = true;
        }
    }

    private Task<bool> ShowDeletePluginConfigWarningModal(string pluginName, bool explainTesting = false)
    {
        this.deletePluginConfigWarningModalOnNextFrame = true;
        this.deletePluginConfigWarningModalPluginName = pluginName;
        this.deletePluginConfigWarningModalExplainTesting = explainTesting;
        this.deletePluginConfigWarningModalTaskCompletionSource = new TaskCompletionSource<bool>();
        return this.deletePluginConfigWarningModalTaskCompletionSource.Task;
    }

    private void DrawDeletePluginConfigWarningModal()
    {
        var modalTitle = Locs.DeletePluginConfigWarningModal_Title;

        if (ImGui.BeginPopupModal(modalTitle, ref this.deletePluginConfigWarningModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            if (this.deletePluginConfigWarningModalExplainTesting)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.WarningForeground);
                ImGui.Text(Locs.DeletePluginConfigWarningModal_ExplainTesting());
                ImGui.PopStyleColor();
            }

            ImGui.Text(Locs.DeletePluginConfigWarningModal_Body(this.deletePluginConfigWarningModalPluginName));
            ImGui.Spacing();

            var buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ((buttonWidth * 2) - (ImGui.GetStyle().ItemSpacing.Y * 2))) / 2);

            if (ImGui.Button(Locs.DeletePluginConfirmWarningModal_Yes, new Vector2(buttonWidth, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.deletePluginConfigWarningModalTaskCompletionSource?.SetResult(true);
            }

            ImGui.SameLine();

            if (ImGui.Button(Locs.DeletePluginConfirmWarningModal_No, new Vector2(buttonWidth, 40)))
            {
                ImGui.CloseCurrentPopup();
                this.deletePluginConfigWarningModalTaskCompletionSource?.SetResult(false);
            }

            ImGui.EndPopup();
        }

        if (this.deletePluginConfigWarningModalOnNextFrame)
        {
            // NOTE(goat): ImGui cannot open a modal if no window is focused, at the moment.
            // If people click out of the installer into the game while a plugin is installing, we won't be able to show a modal if we don't grab focus.
            ImGui.SetWindowFocus(this.WindowName);

            ImGui.OpenPopup(modalTitle);
            this.deletePluginConfigWarningModalOnNextFrame = false;
            this.deletePluginConfigWarningModalDrawing = true;
        }
    }

    private void DrawFeedbackModal()
    {
        var modalTitle = Locs.FeedbackModal_Title;

        if (ImGui.BeginPopupModal(modalTitle, ref this.feedbackModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text(Locs.FeedbackModal_Text(this.feedbackPlugin.Name));

            if (this.feedbackPlugin?.FeedbackMessage != null)
            {
                ImGui.TextWrapped(this.feedbackPlugin.FeedbackMessage);
            }

            if (this.pluginListUpdatable.Any(
                    up => up.InstalledPlugin.Manifest.InternalName == this.feedbackPlugin?.InternalName))
            {
                ImGui.TextColored(ImGuiColors.AttentionForeground, Locs.FeedbackModal_HasUpdate);
            }

            ImGui.Spacing();

            ImGui.InputTextMultiline("###FeedbackContent"u8, ref this.feedbackModalBody, 1000, new Vector2(400, 200));

            ImGui.Spacing();

            ImGui.InputText(Locs.FeedbackModal_ContactInformation, ref this.feedbackModalContact, 100);

            ImGui.SameLine();

            if (ImGui.Button(Locs.FeedbackModal_ContactInformationDiscordButton))
            {
                Process.Start(new ProcessStartInfo(Locs.FeedbackModal_ContactInformationDiscordUrl)
                {
                    UseShellExecute = true,
                });
            }

            ImGui.Text(Locs.FeedbackModal_ContactInformationHelp);

            ImGui.TextColored(ImGuiColors.WarningForeground, Locs.FeedbackModal_ContactInformationWarning);

            ImGui.Spacing();

            ImGui.BeginDisabled();
            ImGui.Checkbox(Locs.FeedbackModal_IncludeLastError, ref this.feedbackModalIncludeException);
            ImGui.EndDisabled();
            
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.FeedbackModal_IncludeLastErrorHint);

            ImGui.Spacing();

            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.FeedbackModal_Hint);

            var buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - buttonWidth) / 2);

            if (ImGui.Button(Locs.ErrorModalButton_Ok, new Vector2(buttonWidth, 40)))
            {
                if (string.IsNullOrWhiteSpace(this.feedbackModalContact))
                {
                    this.ShowErrorModal(Locs.FeedbackModal_ContactInformationRequired)
                        .ContinueWith(_ =>
                        {
                            this.feedbackModalOnNextFrameDontClear = true;
                            this.feedbackModalOnNextFrame = true;
                        });
                }
                else
                {
                    if (this.feedbackPlugin != null)
                    {
                        Task.Run(async () => await BugBait.SendFeedback(
                                                 this.feedbackPlugin,
                                                 this.feedbackIsTesting,
                                                 this.feedbackModalBody,
                                                 this.feedbackModalContact,
                                                 this.feedbackModalIncludeException))
                            .ContinueWith(
                                t =>
                                {
                                    var notif = Service<NotificationManager>.Get();
                                    if (t.IsCanceled || t.IsFaulted)
                                    {
                                        notif.AddNotification(
                                            Locs.FeedbackModal_NotificationError,
                                            Locs.FeedbackModal_Title,
                                            NotificationType.Error);
                                    }
                                    else
                                    {
                                        notif.AddNotification(
                                            Locs.FeedbackModal_NotificationSuccess,
                                            Locs.FeedbackModal_Title,
                                            NotificationType.Success);
                                    }
                                });
                    }
                    else
                    {
                        Log.Error("FeedbackPlugin was null.");
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
            ImGui.OpenPopup(modalTitle);
            this.feedbackModalOnNextFrame = false;
            this.feedbackModalDrawing = true;
            if (!this.feedbackModalOnNextFrameDontClear)
            {
                this.feedbackModalBody = string.Empty;
                this.feedbackModalContact = Service<DalamudConfiguration>.Get().LastFeedbackContactDetails;
                this.feedbackModalIncludeException = true;
            }
            else
            {
                this.feedbackModalOnNextFrameDontClear = false;
            }
        }
    }

    private void DrawChangelogList(bool displayDalamud, bool displayPlugins)
    {
        if (this.pluginListInstalled.Count == 0)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.TabBody_SearchNoInstalled);
            return;
        }

        if (this.dalamudChangelogRefreshTask?.IsFaulted == true ||
            this.dalamudChangelogRefreshTask?.IsCanceled == true)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.TabBody_ChangelogError);
            return;
        }

        if (this.dalamudChangelogManager?.Changelogs == null)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.TabBody_LoadingPlugins);

            if (this.dalamudChangelogManager != null &&
                this.dalamudChangelogRefreshTask == null)
            {
                this.dalamudChangelogRefreshTaskCts = new CancellationTokenSource();
                this.dalamudChangelogRefreshTask =
                    Task.Run(this.dalamudChangelogManager.ReloadChangelogAsync, this.dalamudChangelogRefreshTaskCts.Token)
                        .ContinueWith(t =>
                        {
                            if (!t.IsCompletedSuccessfully)
                            {
                                Log.Error(t.Exception, "Failed to load changelogs.");
                            }
                        });
            }

            return;
        }

        IEnumerable<IChangelogEntry> changelogs = null;
        if (displayDalamud && displayPlugins && this.dalamudChangelogManager.Changelogs != null)
        {
            changelogs = this.dalamudChangelogManager.Changelogs;
        }
        else if (displayDalamud && this.dalamudChangelogManager.Changelogs != null)
        {
            changelogs = this.dalamudChangelogManager.Changelogs.OfType<DalamudChangelogEntry>();
        }
        else if (displayPlugins)
        {
            changelogs = this.dalamudChangelogManager.Changelogs.OfType<PluginChangelogEntry>();
        }

        var sortedChangelogs = changelogs?.Where(x => this.searchText.IsNullOrWhitespace() || new FuzzyMatcher(this.searchText.ToLowerInvariant(), MatchMode.FuzzyParts).Matches(x.Title.ToLowerInvariant()) > 0)
                                                            .OrderByDescending(x => x.Date).ToList();

        if (sortedChangelogs == null || sortedChangelogs.Count == 0)
        {
            ImGui.TextColored(
                ImGuiColors.DalamudGrey2,
                this.pluginListInstalled.Any(plugin => !plugin.Manifest.Changelog.IsNullOrEmpty())
                    ? Locs.TabBody_SearchNoMatching
                    : Locs.TabBody_ChangelogNone);

            return;
        }

        foreach (var logEntry in sortedChangelogs)
        {
            this.DrawChangelog(logEntry);
        }
    }

#pragma warning disable SA1201
    private record PluginInstallerAvailablePluginProxy(RemotePluginManifest? RemoteManifest, LocalPlugin? LocalPlugin);

    private IEnumerable<PluginInstallerAvailablePluginProxy> GatherProxies()
    {
        var proxies = new List<PluginInstallerAvailablePluginProxy>();

        var availableManifests = this.pluginListAvailable;
        var installedPlugins = this.pluginListInstalled.ToList(); // Copy intended

        if (availableManifests.Count == 0)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.TabBody_SearchNoCompatible);
            return proxies;
        }

        var filteredAvailableManifests = availableManifests
                                         .Where(rm => !this.IsManifestFiltered(rm))
                                         .ToList();

        if (filteredAvailableManifests.Count == 0)
        {
            return proxies;
        }

        // Go through all AVAILABLE manifests, associate them with a NON-DEV local plugin, if one is available, and remove it from the pile
        foreach (var availableManifest in this.categoryManager.GetCurrentCategoryContent(filteredAvailableManifests).Cast<RemotePluginManifest>())
        {
            var plugin = this.pluginListInstalled
                             .FirstOrDefault(plugin =>
                             {
                                 var installFrom = plugin.Manifest.InstalledFromUrl;
                                 if (installFrom == SpecialPluginSource.MainRepo)
                                     installFrom = Service<DalamudConfiguration>.Get().MainRepoUrl;
         
                                 return plugin.Manifest.InternalName == availableManifest.InternalName &&
                                        availableManifest.SourceRepo.PluginMasterUrl.Equals(installFrom) &&
                                        !plugin.IsDev;
                             });

            // We "consumed" this plugin from the pile and remove it.
            if (plugin != null)
            {
                installedPlugins.Remove(plugin);
                proxies.Add(new PluginInstallerAvailablePluginProxy(availableManifest, plugin));

                continue;
            }

            proxies.Add(new PluginInstallerAvailablePluginProxy(availableManifest, null));
        }

        // Now, add all applicable local plugins that haven't been "used up", in most cases either dev or orphaned plugins.
        foreach (var installedPlugin in installedPlugins)
        {
            if (this.IsManifestFiltered(installedPlugin.Manifest))
                continue;

            // TODO: We should also check categories here, for good measure

            proxies.Add(new PluginInstallerAvailablePluginProxy(null, installedPlugin));
        }

        var configuration = Service<DalamudConfiguration>.Get();
        bool IsProxyHidden(PluginInstallerAvailablePluginProxy proxy)
        {
            var isHidden =
                configuration.HiddenPluginInternalName.Contains(proxy.RemoteManifest?.InternalName);
            if (this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.Hidden)
                return isHidden;
            return !isHidden;
        }

        // Filter out plugins that are not hidden
        proxies = proxies.Where(IsProxyHidden).ToList();

        return proxies;
    }
#pragma warning restore SA1201

#pragma warning disable SA1204
    private static void DrawMutedBodyText(string text, float paddingBefore, float paddingAfter)
#pragma warning restore SA1204
    {
        ImGuiHelpers.ScaledDummy(paddingBefore);

        using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
        {
            foreach (var line in text.Split('\n'))
            {
                ImGuiHelpers.CenteredText(line);
            }
        }

        ImGuiHelpers.ScaledDummy(paddingAfter);
    }

    private void DrawAvailablePluginListSoil()
    {
        var proxies = this.GatherProxies().ToList();
        if (proxies.Count == 0)
            return; // 没有插件可显示
        
        // 按仓库 URL 对插件分组
        var proxyGroups = proxies
            .GroupBy(p =>
            {
                if (p.LocalPlugin is { IsDev: false })
                    return p.LocalPlugin.Manifest.InstalledFromUrl == SpecialPluginSource.MainRepo ? "主库" : p.LocalPlugin.Manifest.InstalledFromUrl;
                if (p.RemoteManifest != null)
                    return p.RemoteManifest.SourceRepo.IsThirdParty ? p.RemoteManifest.SourceRepo.PluginMasterUrl : "主库";
                return "开发版插件";
            })
            .OrderBy(g => g.Key)
            .ToList();
        
        var i = 0;
        foreach (var group in proxyGroups)
        {
            var repoUrl = group.Key;
            var hasItems = false;
            
            // 绘制仓库标题
            if (!string.IsNullOrEmpty(repoUrl))
            {
                if (ImGui.Button($"{repoUrl}###repo{i}",
                                 new(ImGui.GetContentRegionAvail().X, 40f + ImGui.GetTextLineHeightWithSpacing())))
                    ImGui.SetClipboardText(repoUrl);
            }
            
            // 绘制该仓库下的所有插件
            foreach (var proxy in group)
            {
                hasItems = true;
                
                IPluginManifest applicableManifest = proxy.LocalPlugin != null ? proxy.LocalPlugin.Manifest : proxy.RemoteManifest;

                if (applicableManifest == null)
                    throw new Exception("Could not determine manifest for available plugin");
                
                ImGui.PushID($"{applicableManifest.InternalName}{applicableManifest.AssemblyVersion}");
                
                if (proxy.LocalPlugin != null)
                {
                    var update = this.pluginListUpdatable.FirstOrDefault(up => up.InstalledPlugin == proxy.LocalPlugin);
                    this.DrawInstalledPlugin(proxy.LocalPlugin, i++, proxy.RemoteManifest, update);
                }
                else if (proxy.RemoteManifest != null)
                {
                    this.DrawAvailablePlugin(proxy.RemoteManifest, i++);
                }

                ImGui.PopID();
            }
            
            // 如果没有显示任何项目，绘制一个提示
            if (!hasItems)
            {
                ImGui.TextColored(ImGuiColors.DalamudGrey2, 
                    string.IsNullOrWhiteSpace(this.searchText) 
                        ? "此仓库未找到可用插件" 
                        : $"未找到匹配 \"{this.searchText}\" 的插件");
            }
        }

        // Reset the category to "All" if we're on the "Hidden" category and there are no hidden plugins (we removed the last one)
        if (i == 0 && this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.Hidden)
        {
            this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
        }

        using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
        {
            var hasSearch = !this.searchText.IsNullOrEmpty();

            if (i == 0 && !hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_NoPluginsAvailable, 60, 20);
            }
            else if (i == 0 && hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_SearchNoMatching, 60, 20);
            }
            else if (hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_NoMoreResultsFor(this.searchText), 20, 20);
            }
        }
    }

    private void DrawAvailablePluginList()
    {
        var i = 0;
        foreach (var proxy in this.GatherProxies())
        {
            IPluginManifest applicableManifest = proxy.LocalPlugin != null ? proxy.LocalPlugin.Manifest : proxy.RemoteManifest;

            if (applicableManifest == null)
                throw new Exception("Could not determine manifest for available plugin");

            ImGui.PushID($"{applicableManifest.InternalName}{applicableManifest.AssemblyVersion}");

            if (proxy.LocalPlugin != null)
            {
                var update = this.pluginListUpdatable.FirstOrDefault(up => up.InstalledPlugin == proxy.LocalPlugin);
                this.DrawInstalledPlugin(proxy.LocalPlugin, i++, proxy.RemoteManifest, update);
            }
            else if (proxy.RemoteManifest != null)
            {
                this.DrawAvailablePlugin(proxy.RemoteManifest, i++);
            }

            ImGui.PopID();
        }

        // Reset the category to "All" if we're on the "Hidden" category and there are no hidden plugins (we removed the last one)
        if (i == 0 && this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.Hidden)
        {
            this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
        }

        using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
        {
            var hasSearch = !this.searchText.IsNullOrEmpty();

            if (i == 0 && !hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_NoPluginsAvailable, 60, 20);
            }
            else if (i == 0 && hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_SearchNoMatching, 60, 20);
            }
            else if (hasSearch)
            {
                DrawMutedBodyText(Locs.TabBody_NoMoreResultsFor(this.searchText), 20, 20);
            }
        }
    }

    private void DrawInstalledPluginList(InstalledPluginListFilter filter)
    {
        var pluginList = this.pluginListInstalled;
        var manager = Service<PluginManager>.Get();

        if (pluginList.Count == 0)
        {
            DrawMutedBodyText(Locs.TabBody_SearchNoInstalled, 60, 20);
            return;
        }

        var filteredList = pluginList
                           .Where(plugin => !this.IsManifestFiltered(plugin.Manifest))
                           .OrderBy(x => !x.IsDev ? x.Manifest.InstalledFromUrl : string.Empty)
                           .ToList();

        if (filteredList.Count == 0)
        {
            DrawMutedBodyText(Locs.TabBody_SearchNoMatching, 60, 20);
            return;
        }

        var drewAny = false;
        var i = 0;
        var lastRepoUrl = string.Empty;
        foreach (var plugin in filteredList)
        {
            if (filter == InstalledPluginListFilter.Testing && !manager.HasTestingOptIn(plugin.Manifest))
                continue;

            if (filter == InstalledPluginListFilter.Enabled && (!plugin.IsWantedByAnyProfile || plugin.IsOutdated || plugin.IsBanned || plugin.IsOrphaned || plugin.IsDecommissioned))
                continue;

            if (filter == InstalledPluginListFilter.Disabled && (plugin.IsWantedByAnyProfile || plugin.IsOutdated || plugin.IsBanned || plugin.IsOrphaned || plugin.IsDecommissioned))
                continue;

            if (filter == InstalledPluginListFilter.Incompatible && !(plugin.IsOutdated || plugin.IsBanned || plugin.IsOrphaned || plugin.IsDecommissioned))
                continue;

            // Find applicable update and manifest, if we have them
            AvailablePluginUpdate? update = null;
            RemotePluginManifest? remoteManifest = null;

            if (filter != InstalledPluginListFilter.Dev)
            {
                update = this.pluginListUpdatable.FirstOrDefault(up => up.InstalledPlugin == plugin);
                if (filter == InstalledPluginListFilter.Updateable && update == null)
                    continue;

                // Find the applicable remote manifest
                remoteManifest = this.pluginListAvailable
                                         .FirstOrDefault(rm =>
                                         {
                                             var installFrom = plugin.Manifest.InstalledFromUrl;
                                             if (installFrom == SpecialPluginSource.MainRepo)
                                                 installFrom = Service<DalamudConfiguration>.Get().MainRepoUrl;
                                             return rm.InternalName == plugin.Manifest.InternalName &&
                                                    rm.SourceRepo.PluginMasterUrl.Equals(installFrom);
                                         });
            }
            else if (!plugin.IsDev)
            {
                continue;
            }

            var currentRepoUrl = remoteManifest?.SourceRepo.PluginMasterUrl ?? plugin.Manifest.InstalledFromUrl;
            if (!plugin.IsDev && lastRepoUrl != currentRepoUrl)
            {
                lastRepoUrl = currentRepoUrl;
                var repoText = lastRepoUrl == Service<DalamudConfiguration>.Get().MainRepoUrl ? "主库" : lastRepoUrl;
                if (ImGui.Button($"{repoText}",
                                 new(ImGui.GetContentRegionAvail().X, 40f + ImGui.GetTextLineHeightWithSpacing())))
                    ImGui.SetClipboardText(lastRepoUrl);
            }

            this.DrawInstalledPlugin(plugin, i++, remoteManifest, update);
            drewAny = true;
        }

        if (!drewAny)
        {
            var text = filter switch
            {
                InstalledPluginListFilter.None => Locs.TabBody_NoPluginsInstalled,
                InstalledPluginListFilter.Testing => Locs.TabBody_NoPluginsTesting,
                InstalledPluginListFilter.Updateable => Locs.TabBody_NoPluginsUpdateable,
                InstalledPluginListFilter.Dev => Locs.TabBody_NoPluginsDev,
                InstalledPluginListFilter.Enabled => Locs.TabBody_NoPluginsEnabled,
                InstalledPluginListFilter.Disabled => Locs.TabBody_NoPluginsDisabled,
                InstalledPluginListFilter.Incompatible => Locs.TabBody_NoPluginsIncompatible,
                _ => throw new ArgumentException(null, nameof(filter)),
            };

            ImGuiHelpers.ScaledDummy(60);

            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
            {
                foreach (var line in text.Split('\n'))
                {
                    ImGuiHelpers.CenteredText(line);
                }
            }
        }
        else if (!this.searchText.IsNullOrEmpty())
        {
            DrawMutedBodyText(Locs.TabBody_NoMoreResultsFor(this.searchText), 20, 20);
            ImGuiHelpers.ScaledDummy(20);
        }
    }

    private void DrawPluginCategories()
    {
        var useContentHeight = -40f; // button height + spacing
        var useMenuWidth = 180f;     // works fine as static value, table can be resized by user

        var useContentWidth = ImGui.GetContentRegionAvail().X;

        using var installerMainChild = ImRaii.Child("InstallerCategories"u8, new Vector2(useContentWidth, useContentHeight * ImGuiHelpers.GlobalScale));
        if (installerMainChild)
        {
            using var style = ImRaii.PushStyle(ImGuiStyleVar.CellPadding, ImGuiHelpers.ScaledVector2(5, 0));

            try
            {
                using (var categoriesChild = ImRaii.Child("InstallerCategoriesSelector"u8, new Vector2(useMenuWidth * ImGuiHelpers.GlobalScale, -1), false))
                {
                    if (categoriesChild)
                    {
                        this.DrawPluginCategorySelectors();
                    }
                }

                ImGui.SameLine();

                using var scrollingChild =
                    ImRaii.Child("ScrollingPlugins"u8, new Vector2(-1, -1), false, ImGuiWindowFlags.NoBackground);
                if (scrollingChild)
                {
                    try
                    {
                        this.DrawPluginCategoryContent();
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "Could not draw category content");
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Could not draw plugin categories");
            }
        }
    }

    private void DrawPluginCategorySelectors()
    {
        var colorSearchHighlight = Vector4.One;
        unsafe
        {
            var colorPtr = ImGui.GetStyleColorVec4(ImGuiCol.NavHighlight);
            if (colorPtr != null)
            {
                colorSearchHighlight = *colorPtr;
            }
        }

        foreach (var groupInfo in this.categoryManager.GroupList)
        {
            var canShowGroup = (groupInfo.GroupKind != PluginCategoryManager.GroupKind.DevTools) || this.hasDevPlugins;
            if (!canShowGroup)
            {
                continue;
            }

            var isCurrent = groupInfo.GroupKind == this.categoryManager.CurrentGroupKind;
            ImGui.SetNextItemOpen(isCurrent);
            if (ImGui.CollapsingHeader(groupInfo.Name, isCurrent ? ImGuiTreeNodeFlags.OpenOnDoubleClick : ImGuiTreeNodeFlags.None))
            {
                if (!isCurrent)
                {
                    this.categoryManager.CurrentGroupKind = groupInfo.GroupKind;

                    // Reset search text when switching groups
                    this.searchText = string.Empty;
                }

                ImGui.Indent();
                var categoryItemSize = new Vector2(ImGui.GetContentRegionAvail().X - (5 * ImGuiHelpers.GlobalScale), ImGui.GetTextLineHeight());
                foreach (var categoryKind in groupInfo.Categories)
                {
                    var categoryInfo = this.categoryManager.CategoryList.First(x => x.CategoryKind == categoryKind);

                    switch (categoryInfo.Condition)
                    {
                        case PluginCategoryManager.CategoryInfo.AppearCondition.None:
                            // Do nothing
                            break;
                        case PluginCategoryManager.CategoryInfo.AppearCondition.DoPluginTest:
                            if (!Service<DalamudConfiguration>.Get().DoPluginTest)
                                continue;
                            break;
                                                  case PluginCategoryManager.CategoryInfo.AppearCondition.AnyHiddenPlugins:
                             if (!this.hasHiddenPlugins)
                                  continue;
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }

                    var hasSearchHighlight = this.categoryManager.IsCategoryHighlighted(categoryInfo.CategoryKind);
                    if (hasSearchHighlight)
                    {
                        ImGui.PushStyleColor(ImGuiCol.Text, colorSearchHighlight);
                    }

                    if (ImGui.Selectable(categoryInfo.Name, this.categoryManager.CurrentCategoryKind == categoryKind, ImGuiSelectableFlags.None, categoryItemSize))
                    {
                        this.categoryManager.CurrentCategoryKind = categoryKind;
                    }

                    if (hasSearchHighlight)
                    {
                        ImGui.PopStyleColor();
                    }
                }

                ImGui.Unindent();
                ImGuiHelpers.ScaledDummy(5);
            }
        }
    }

    private void DrawPluginCategoryContent()
    {
        var ready = this.DrawPluginListLoading();
        if (!this.categoryManager.IsSelectionValid || !ready)
        {
            return;
        }

        void DrawWarningIcon()
        {
            ImGuiHelpers.ScaledDummy(10);

            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.WarningForeground);
            ImGui.PushFont(InterfaceManager.IconFont);
            ImGuiHelpers.CenteredText(FontAwesomeIcon.ExclamationTriangle.ToIconString());
            ImGui.PopFont();
            ImGui.PopStyleColor();
        }

        void DrawLinesCentered(string text)
        {
            var lines = text.Split('\n');
            foreach (var line in lines)
            {
                ImGuiHelpers.CenteredText(line);
            }
        }

        var pm = Service<PluginManager>.Get();
        if (pm.SafeMode)
        {
            DrawWarningIcon();
            DrawLinesCentered(Locs.SafeModeDisclaimer);

            ImGuiHelpers.ScaledDummy(10);
        }

        if (this.staleDalamudNewVersion != null)
        {
            DrawWarningIcon();
            DrawLinesCentered("A new version of Dalamud is available.\n" +
                              "Please restart the game to ensure compatibility with updated plugins.\n" +
                              $"old: {Versioning.GetScmVersion()} new: {this.staleDalamudNewVersion}");

            ImGuiHelpers.ScaledDummy(10);
        }

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, ImGuiHelpers.ScaledVector2(1, 3));

        var groupInfo = this.categoryManager.CurrentGroup;
        if (this.categoryManager.IsContentDirty)
        {
            // reset opened list of collapsibles when switching between categories
            this.openPluginCollapsibles.Clear();

            // do NOT reset dirty flag when Available group is selected, it will be handled by DrawAvailablePluginList()
            if (groupInfo.GroupKind != PluginCategoryManager.GroupKind.Available)
            {
                this.categoryManager.ResetContentDirty();
            }
        }

        switch (groupInfo.GroupKind)
        {
            case PluginCategoryManager.GroupKind.DevTools:
                // this one is never sorted and remains in hardcoded order from group ctor
                switch (this.categoryManager.CurrentCategoryKind)
                {
                    case PluginCategoryManager.CategoryKind.DevInstalled:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Dev);
                        break;

                    case PluginCategoryManager.CategoryKind.IconTester:
                        this.DrawImageTester();
                        break;

                    default:
                        ImGui.Text("You found a mysterious category. Please keep it to yourself."u8);
                        break;
                }

                break;
            case PluginCategoryManager.GroupKind.Installed:
                switch (this.categoryManager.CurrentCategoryKind)
                {
                    case PluginCategoryManager.CategoryKind.All:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.None);
                        break;

                    case PluginCategoryManager.CategoryKind.IsTesting:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Testing);
                        break;

                    case PluginCategoryManager.CategoryKind.UpdateablePlugins:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Updateable);
                        break;

                    case PluginCategoryManager.CategoryKind.EnabledPlugins:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Enabled);
                        break;

                    case PluginCategoryManager.CategoryKind.DisabledPlugins:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Disabled);
                        break;

                    case PluginCategoryManager.CategoryKind.IncompatiblePlugins:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Incompatible);
                        break;

                    case PluginCategoryManager.CategoryKind.PluginProfiles:
                        this.profileManagerWidget.Draw();
                        break;

                    default:
                        ImGui.Text("You found a secret category. Please feel a sense of pride and accomplishment."u8);
                        break;
                }

                break;
            case PluginCategoryManager.GroupKind.Changelog:
                switch (this.categoryManager.CurrentCategoryKind)
                {
                    case PluginCategoryManager.CategoryKind.All:
                        this.DrawChangelogList(true, true);
                        break;

                    case PluginCategoryManager.CategoryKind.DalamudChangelogs:
                        this.DrawChangelogList(true, false);
                        break;

                    case PluginCategoryManager.CategoryKind.PluginChangelogs:
                        this.DrawChangelogList(false, true);
                        break;

                    default:
                        ImGui.Text("You found a quiet category. Please don't wake it up."u8);
                        break;
                }

                break;
            default:
                if (Service<DalamudConfiguration>.Get().UseSoilPluginManager)
                    this.DrawAvailablePluginListSoil();
                else
                    this.DrawAvailablePluginList();
                break;
        }

        ImGui.PopStyleVar();
    }

    private void DrawImageTester()
    {
        var sectionSize = ImGuiHelpers.GlobalScale * 66;
        var startCursor = ImGui.GetCursorPos();

        ImGui.PushStyleColor(ImGuiCol.Button, true ? new Vector4(0.5f, 0.5f, 0.5f, 0.1f) : Vector4.Zero);

        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.5f, 0.5f, 0.5f, 0.2f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.5f, 0.5f, 0.5f, 0.35f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 0);

        ImGui.Button($"###pluginTesterCollapsibleBtn", new Vector2(ImGui.GetWindowWidth() - (ImGuiHelpers.GlobalScale * 35), sectionSize));

        ImGui.PopStyleVar();

        ImGui.PopStyleColor(3);

        ImGui.SetCursorPos(startCursor);

        var hasIcon = this.testerIcon?.IsCompletedSuccessfully is true;

        var iconTex = this.imageCache.DefaultIcon;
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
        ImGui.Text("My Cool Plugin"u8);

        // Download count
        var downloadCountText = Locs.PluginBody_AuthorWithDownloadCount("Plugin Enjoyer", 69420);

        ImGui.SameLine();
        ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadCountText);

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        // Description
        ImGui.TextWrapped("This plugin does very many great things."u8);

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);

        ImGuiHelpers.ScaledDummy(5);

        ImGui.Indent();

        // Description
        ImGui.TextWrapped("This is a description.\nIt has multiple lines.\nTruly descriptive."u8);

        ImGuiHelpers.ScaledDummy(5);

        // Controls
        var disabled = this.updateStatus == OperationStatus.InProgress || this.installStatus == OperationStatus.InProgress;

        var versionString = "1.0.0.0";

        if (disabled)
        {
            ImGuiComponents.DisabledButton(Locs.PluginButton_InstallVersion(versionString));
        }
        else
        {
            var buttonText = Locs.PluginButton_InstallVersion(versionString);
            ImGui.Button($"{buttonText}##{buttonText}testing");
        }

        this.DrawVisitRepoUrlButton("https://google.com", true);

        if (this.testerImages != null)
        {
            ImGuiHelpers.ScaledDummy(5);

            const float thumbFactor = 2.7f;

            var scrollBarSize = 15;
            ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, scrollBarSize);
            ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, Vector4.Zero);

            var width = ImGui.GetWindowWidth();

            if (ImGui.BeginChild(
                    "pluginTestingImageScrolling"u8,
                    new Vector2(width - (70 * ImGuiHelpers.GlobalScale), (PluginImageCache.PluginImageHeight / thumbFactor) + scrollBarSize),
                    false,
                    ImGuiWindowFlags.HorizontalScrollbar |
                    ImGuiWindowFlags.NoScrollWithMouse |
                    ImGuiWindowFlags.NoBackground))
            {
                if (this.testerImages != null && this.testerImages is { Length: > 0 })
                {
                    for (var i = 0; i < this.testerImages.Length; i++)
                    {
                        var popupId = $"pluginTestingImage{i}";
                        var imageTask = this.testerImages[i];
                        if (imageTask == null)
                            continue;

                        if (!imageTask.IsCompleted)
                        {
                            ImGui.Text("Loading..."u8);
                            continue;
                        }

                        if (imageTask.Exception is not null)
                        {
                            ImGui.Text(imageTask.Exception.ToString());
                            continue;
                        }

                        var image = imageTask.Result;

                        ImGui.PushStyleVar(ImGuiStyleVar.PopupBorderSize, 0);
                        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
                        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                        if (ImGui.BeginPopup(popupId))
                        {
                            if (ImGui.ImageButton(image.Handle, new Vector2(image.Width, image.Height)))
                                ImGui.CloseCurrentPopup();

                            ImGui.EndPopup();
                        }

                        ImGui.PopStyleVar(3);

                        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                        float xAct = image.Width;
                        float yAct = image.Height;
                        float xMax = PluginImageCache.PluginImageWidth;
                        float yMax = PluginImageCache.PluginImageHeight;

                        // scale image if undersized
                        if (xAct < xMax && yAct < yMax)
                        {
                            var scale = Math.Min(xMax / xAct, yMax / yAct);
                            xAct *= scale;
                            yAct *= scale;
                        }

                        var size = ImGuiHelpers.ScaledVector2(xAct / thumbFactor, yAct / thumbFactor);
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

        static void CheckImageSize(Task<IDalamudTextureWrap>? imageTask, int maxWidth, int maxHeight, bool requireSquare)
        {
            if (imageTask == null)
                return;

            if (!imageTask.IsCompleted)
            {
                ImGui.Text("Loading..."u8);
                return;
            }

            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            if (imageTask.Exception is { } exc)
            {
                ImGui.Text(exc.ToString());
            }
            else
            {
                var image = imageTask.Result;
                if (image.Width > maxWidth || image.Height > maxHeight)
                {
                    ImGui.Text(
                        $"Image is larger than the maximum allowed resolution ({image.Width}x{image.Height} > {maxWidth}x{maxHeight})");
                }

                if (requireSquare && image.Width != image.Height)
                    ImGui.Text($"Image must be square! Current size: {image.Width}x{image.Height}");
            }

            ImGui.PopStyleColor();
        }

        ImGui.InputText("Icon Path"u8, ref this.testerIconPath, 1000);
        if (this.testerIcon != null)
            CheckImageSize(this.testerIcon, PluginImageCache.PluginIconWidth, PluginImageCache.PluginIconHeight, true);
        ImGui.InputText("Image 1 Path"u8, ref this.testerImagePaths[0], 1000);
        if (this.testerImages?.Length > 0)
            CheckImageSize(this.testerImages[0], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("Image 2 Path"u8, ref this.testerImagePaths[1], 1000);
        if (this.testerImages?.Length > 1)
            CheckImageSize(this.testerImages[1], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("Image 3 Path"u8, ref this.testerImagePaths[2], 1000);
        if (this.testerImages?.Length > 2)
            CheckImageSize(this.testerImages[2], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("Image 4 Path"u8, ref this.testerImagePaths[3], 1000);
        if (this.testerImages?.Length > 3)
            CheckImageSize(this.testerImages[3], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);
        ImGui.InputText("Image 5 Path"u8, ref this.testerImagePaths[4], 1000);
        if (this.testerImages?.Length > 4)
            CheckImageSize(this.testerImages[4], PluginImageCache.PluginImageWidth, PluginImageCache.PluginImageHeight, false);

        var tm = Service<TextureManager>.Get();
        if (ImGui.Button("Load"u8))
        {
            try
            {
                if (this.testerIcon != null)
                {
                    this.testerIcon.Dispose();
                    this.testerIcon = null;
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

                    _ = this.testerImages[i]?.ToContentDisposedTask();
                    this.testerImages[i] = tm.Shared.GetFromFile(this.testerImagePaths[i]).RentAsync();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Could not load plugin images for testing.");
            }
        }

        ImGui.Checkbox("Failed"u8, ref this.testerError);
        ImGui.Checkbox("Has Update"u8, ref this.testerUpdateAvailable);
    }

    private bool DrawPluginListLoading()
    {
        var pluginManager = Service<PluginManager>.Get();

        var ready = pluginManager.PluginsReady && pluginManager.ReposReady;

        if (!ready)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.TabBody_LoadingPlugins);
        }

        var failedRepos = pluginManager.Repos
                                       .Where(repo => repo.State == PluginRepositoryState.Fail)
                                       .ToArray();

        if (failedRepos.Length > 0)
        {
            var failText = Locs.TabBody_DownloadFailed;
            var aggFailText = failedRepos
                              .Select(repo => $"{failText} ({repo.PluginMasterUrl})")
                              .Aggregate((s1, s2) => $"{s1}\n{s2}");

            ImGui.TextColored(ImGuiColors.ErrorForeground, aggFailText);
        }

        return ready;
    }

    private bool DrawPluginCollapsingHeader(string label, LocalPlugin? plugin, IPluginManifest manifest, PluginHeaderFlags flags, Action drawContextMenuAction, int index)
    {
        var isOpen = this.openPluginCollapsibles.Contains(index);

        var sectionSize = ImGuiHelpers.GlobalScale * 66;

        ImGui.Separator();

        var childId = $"plugin_child_{label}_{plugin?.EffectiveWorkingPluginId}_{manifest.InternalName}";
        const ImGuiWindowFlags childFlags = ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse;

        using var pluginChild = ImRaii.Child(childId, new Vector2(ImGui.GetContentRegionAvail().X, sectionSize), false, childFlags);
        if (!pluginChild)
        {
            return isOpen;
        }

        var startCursor = ImGui.GetCursorPos();

        if (flags.HasFlag(PluginHeaderFlags.IsTesting))
        {
            void DrawCautionTape(Vector2 position, Vector2 size, float stripeWidth, float skewAmount)
            {
                var wdl = ImGui.GetWindowDrawList();

                var windowPos = ImGui.GetWindowPos();
                var scroll = new Vector2(ImGui.GetScrollX(), ImGui.GetScrollY());

                var adjustedPosition = windowPos + position - scroll;

                var yellow = ImGui.ColorConvertFloat4ToU32(new Vector4(1.0f, 0.9f, 0.0f, 0.10f));
                var numStripes = (int)(size.X / stripeWidth) + (int)(size.Y / skewAmount) + 1;  // +1 to cover partial stripe

                for (var i = 0; i < numStripes; i++)
                {
                    var x0 = adjustedPosition.X + i * stripeWidth;
                    var x1 = x0 + stripeWidth;
                    var y0 = adjustedPosition.Y;
                    var y1 = y0 + size.Y;

                    var p0 = new Vector2(x0, y0);
                    var p1 = new Vector2(x1, y0);
                    var p2 = new Vector2(x1 - skewAmount, y1);
                    var p3 = new Vector2(x0 - skewAmount, y1);

                    if (i % 2 != 0)
                        continue;

                    wdl.AddQuadFilled(p0, p1, p2, p3, yellow);
                }
            }

            DrawCautionTape(startCursor + new Vector2(0, 1), new Vector2(ImGui.GetWindowWidth(), sectionSize + ImGui.GetStyle().ItemSpacing.Y), ImGuiHelpers.GlobalScale * 40, 20);
        }

        ImGui.PushStyleColor(ImGuiCol.Button, isOpen ? new Vector4(0.5f, 0.5f, 0.5f, 0.1f) : Vector4.Zero);

        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.5f, 0.5f, 0.5f, 0.2f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.5f, 0.5f, 0.5f, 0.35f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 0);

        ImGui.SetCursorPos(startCursor);

        if (ImGui.Button($"###plugin{index}CollapsibleBtn", new Vector2(ImGui.GetContentRegionAvail().X, sectionSize + ImGui.GetStyle().ItemSpacing.Y)))
        {
            if (isOpen)
            {
                this.openPluginCollapsibles.Remove(index);
            }
            else
            {
                this.openPluginCollapsibles.Add(index);
            }

            isOpen = !isOpen;
        }

        drawContextMenuAction?.Invoke();

        ImGui.PopStyleVar();

        ImGui.PopStyleColor(3);

        ImGui.SetCursorPos(startCursor);

        var pluginDisabled = plugin is { IsWantedByAnyProfile: false };

        var iconSize = ImGuiHelpers.ScaledVector2(64, 64);
        var cursorBeforeImage = ImGui.GetCursorPos();
        var rectOffset = ImGui.GetWindowContentRegionMin() + ImGui.GetWindowPos();

        var overlayAlpha = 1.0f;
        if (ImGui.IsRectVisible(rectOffset + cursorBeforeImage, rectOffset + cursorBeforeImage + iconSize))
        {
            var iconTex = this.imageCache.DefaultIcon;
            var hasIcon = this.imageCache.TryGetIcon(plugin, manifest, flags.HasFlag(PluginHeaderFlags.IsThirdParty), out var cachedIconTex, out var loadedSince);
            if (hasIcon && cachedIconTex != null)
            {
                iconTex = cachedIconTex;
            }

            const float fadeTime = 0.3f;
            var iconAlpha = 1f;

            if (loadedSince.HasValue)
            {
                float EaseOutCubic(float t) => 1 - MathF.Pow(1 - t, 3);

                var secondsSinceLoad = (float)DateTime.Now.Subtract(loadedSince.Value).TotalSeconds;
                var fadeTo = pluginDisabled || flags.HasFlag(PluginHeaderFlags.IsInstallableOutdated) ? 0.4f : 1f;

                float Interp(float to) => Math.Clamp(EaseOutCubic(Math.Min(secondsSinceLoad, fadeTime) / fadeTime) * to, 0, 1);
                iconAlpha = Interp(fadeTo);
                overlayAlpha = Interp(1f);
            }

            ImGui.PushStyleVar(ImGuiStyleVar.Alpha, iconAlpha);
            ImGui.Image(iconTex.Handle, iconSize);
            ImGui.PopStyleVar();

            ImGui.SameLine();
            ImGui.SetCursorPos(cursorBeforeImage);
        }

        var isLoaded = plugin is { IsLoaded: true };

        ImGui.PushStyleVar(ImGuiStyleVar.Alpha, overlayAlpha);
        if (flags.HasFlag(PluginHeaderFlags.UpdateAvailable))
            ImGui.Image(this.imageCache.UpdateIcon.Handle, iconSize);
        else if ((flags.HasFlag(PluginHeaderFlags.HasTrouble) && !pluginDisabled) || flags.HasFlag(PluginHeaderFlags.IsOrphan) || flags.HasFlag(PluginHeaderFlags.IsIncompatible))
            ImGui.Image(this.imageCache.TroubleIcon.Handle, iconSize);
        else if (flags.HasFlag(PluginHeaderFlags.IsInstallableOutdated))
            ImGui.Image(this.imageCache.OutdatedInstallableIcon.Handle, iconSize);
        else if (pluginDisabled)
            ImGui.Image(this.imageCache.DisabledIcon.Handle, iconSize);
        /* NOTE: Replaced by the checkmarks for now, let's see if that is fine
        else if (isLoaded && isThirdParty)
            ImGui.Image(this.imageCache.ThirdInstalledIcon.ImGuiHandle, iconSize);
        else if (isThirdParty)
            ImGui.Image(this.imageCache.ThirdIcon.ImGuiHandle, iconSize);
        */
        else if (isLoaded)
            ImGui.Image(this.imageCache.InstalledIcon.Handle, iconSize);
        else
            ImGui.Dummy(iconSize);
        ImGui.PopStyleVar();

        ImGui.SameLine();

        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        var cursor = ImGui.GetCursorPos();

        // Name
        ImGui.Text(label);

        // Verified Checkmark or dev plugin wrench
        {
            ImGui.SameLine();
            ImGui.Text(" "u8);
            ImGui.SameLine();

            var verifiedOutlineColor = KnownColor.White.Vector() with { W = 0.75f };
            var unverifiedOutlineColor = KnownColor.Black.Vector();
            var verifiedIconColor = KnownColor.RoyalBlue.Vector() with { W = 0.75f };
            var unverifiedIconColor = KnownColor.Orange.Vector();
            var devIconOutlineColor = KnownColor.White.Vector();
            var devIconColor = KnownColor.MediumOrchid.Vector();

            if (plugin is LocalDevPlugin)
                this.DrawFontawesomeIconOutlined(FontAwesomeIcon.Wrench, devIconOutlineColor, devIconColor);
            else if (!flags.HasFlag(PluginHeaderFlags.IsThirdParty))
                this.DrawFontawesomeIconOutlined(FontAwesomeIcon.CheckCircle, verifiedOutlineColor, verifiedIconColor);
            else
                this.DrawFontawesomeIconOutlined(FontAwesomeIcon.ExclamationCircle, unverifiedOutlineColor, unverifiedIconColor);
        }

        // Download count
        var downloadCountText = manifest.DownloadCount > 0
                                    ? Locs.PluginBody_AuthorWithDownloadCount(manifest.Author, manifest.DownloadCount)
                                    : Locs.PluginBody_AuthorWithDownloadCountUnavailable(manifest.Author);

        ImGui.SameLine();
        ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadCountText);

        if (flags.HasFlag(PluginHeaderFlags.IsNew))
        {
            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.TankBlue, Locs.PluginTitleMod_New);
        }

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        // Outdated warning
        if (flags.HasFlag(PluginHeaderFlags.IsIncompatible))
        {
            using var color = ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped(Locs.PluginBody_Incompatible);
        }
        else if (plugin is { IsOutdated: true, IsBanned: false } || flags.HasFlag(PluginHeaderFlags.IsInstallableOutdated))
        {
            using var color = ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            var bodyText = $"插件 API 版本 ({plugin?.Manifest.DalamudApiLevel ?? 0}) 与 Dalamud API 版本 ({PluginManager.DalamudApiLevel}) 不对应, 无法使用" + " ";
            if (flags.HasFlag(PluginHeaderFlags.UpdateAvailable))
                bodyText += "\n存在可用更新, 可以尝试更新后再试";
            else
                bodyText += "\n请静待插件或框架 API 版本相匹配";
            
            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudRed))
                ImGui.TextWrapped(bodyText);
        }
        else if (plugin is { IsBanned: true })
        {
            // Banned warning
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            var bodyText = plugin.BanReason.IsNullOrEmpty()
                               ? Locs.PluginBody_Banned
                               : Locs.PluginBody_BannedReason(plugin.BanReason);
            bodyText += " ";

            if (flags.HasFlag(PluginHeaderFlags.UpdateAvailable))
                bodyText += "\n" + Locs.PluginBody_Outdated_CanNowUpdate;
            else
                bodyText += Locs.PluginBody_Outdated_WaitForUpdate;

            ImGui.TextWrapped(bodyText);

            ImGui.PopStyleColor();
        }
        else if (plugin is { IsOrphaned: true })
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped(Locs.PluginBody_Orphaned);
            ImGui.PopStyleColor();
        }
        else if (plugin is { IsDecommissioned: true, IsThirdParty: false })
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped(Locs.PluginBody_NoServiceOfficial);
            ImGui.PopStyleColor();
        }
        else if (plugin is { IsDecommissioned: true, IsThirdParty: true })
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            ImGui.TextWrapped(
                flags.HasFlag(PluginHeaderFlags.MainRepoCrossUpdate)
                    ? Locs.PluginBody_NoServiceThirdCrossUpdate
                    : Locs.PluginBody_NoServiceThird);

            ImGui.PopStyleColor();
        }
        else if (plugin != null && !plugin.CheckPolicy())
        {
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped(Locs.PluginBody_Policy);
            ImGui.PopStyleColor();
        }
        else if (plugin is { State: PluginState.LoadError or PluginState.DependencyResolutionFailed })
        {
            // Load failed warning
            ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped(Locs.PluginBody_LoadFailed);
            ImGui.PopStyleColor();
        }

        ImGui.SetCursorPosX(cursor.X);

        // Description
        if (plugin is null or { IsOutdated: false, IsBanned: false } && !flags.HasFlag(PluginHeaderFlags.HasTrouble))
        {
            if (!string.IsNullOrWhiteSpace(manifest.Punchline))
            {
                ImGui.TextWrapped(manifest.Punchline);
            }
            else if (!string.IsNullOrWhiteSpace(manifest.Description))
            {
                const int punchlineLen = 200;
                var firstLine = manifest.Description.Split(['\r', '\n'])[0];

                ImGui.TextWrapped(firstLine.Length < punchlineLen
                                                 ? firstLine
                                                 : firstLine[..punchlineLen]);
            }
        }

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);

        return isOpen;
    }

    private void DrawChangelog(IChangelogEntry log)
    {
        ImGui.Separator();

        var startCursor = ImGui.GetCursorPos();

        var iconSize = ImGuiHelpers.ScaledVector2(64, 64);
        var cursorBeforeImage = ImGui.GetCursorPos();
        var rectOffset = ImGui.GetWindowContentRegionMin() + ImGui.GetWindowPos();
        if (ImGui.IsRectVisible(rectOffset + cursorBeforeImage, rectOffset + cursorBeforeImage + iconSize))
        {
            IDalamudTextureWrap icon;
            if (log is PluginChangelogEntry pluginLog)
            {
                icon = this.imageCache.DefaultIcon;
                var hasIcon = this.imageCache.TryGetIcon(pluginLog.Plugin, pluginLog.Plugin.Manifest, pluginLog.Plugin.IsThirdParty, out var cachedIconTex, out _);
                if (hasIcon && cachedIconTex != null)
                {
                    icon = cachedIconTex;
                }
            }
            else
            {
                icon = this.imageCache.CorePluginIcon;
            }

            ImGui.Image(icon.Handle, iconSize);
        }
        else
        {
            ImGui.Dummy(iconSize);
        }

        ImGui.SameLine();

        ImGuiHelpers.ScaledDummy(5);

        ImGui.SameLine();
        var cursor = ImGui.GetCursorPos();
        ImGui.Text(log.Title);

        ImGui.SameLine();
        ImGui.TextColored(ImGuiColors.DalamudGrey3, $" v{log.Version}");
        if (log.Author != null)
        {
            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.DalamudGrey3, Locs.PluginBody_AuthorWithoutDownloadCount(log.Author));
        }

        if (log.Date != DateTime.MinValue)
        {
            var whenText = log.Date.LocRelativePastLong();
            var whenSize = ImGui.CalcTextSize(whenText);
            ImGui.SameLine(ImGui.GetWindowWidth() - whenSize.X - (25 * ImGuiHelpers.GlobalScale));
            ImGui.TextColored(ImGuiColors.DalamudGrey3, whenText);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Published on " + log.Date.LocAbsolute());
        }

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        ImGui.TextWrapped(log.Text);

        var endCursor = ImGui.GetCursorPos();

        var sectionSize = Math.Max(
            66 * ImGuiHelpers.GlobalScale, // min size due to icons
            endCursor.Y - startCursor.Y);

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);
    }

    private void DrawAvailablePlugin(RemotePluginManifest manifest, int index)
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var canUseTesting = pluginManager.CanUseTesting(manifest);
        var useTesting = pluginManager.UseTesting(manifest);
        var wasSeen = this.WasPluginSeen(manifest.InternalName);

        var effectiveApiLevel = useTesting ? manifest.TestingDalamudApiLevel.Value : manifest.DalamudApiLevel;
        var isOutdated = effectiveApiLevel < PluginManager.DalamudApiLevel;

        var isIncompatible = manifest.MinimumDalamudVersion != null &&
                             manifest.MinimumDalamudVersion > Versioning.GetAssemblyVersionParsed();

        var enableInstallButton = this.updateStatus != OperationStatus.InProgress &&
                                  this.installStatus != OperationStatus.InProgress &&
                                  !isOutdated &&
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
            label += Locs.PluginTitleMod_TestingVersion;
        }
        else if (manifest.IsTestingExclusive)
        {
            label += Locs.PluginTitleMod_TestingExclusive;
        }
        else if (canUseTesting)
        {
            label += Locs.PluginTitleMod_TestingAvailable;
        }

        if (isIncompatible)
        {
            label += Locs.PluginTitleMod_Incompatible;
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

            // Installable from
            var repoText = Locs.PluginBody_Plugin3rdPartyRepo(manifest.SourceRepo.PluginMasterUrl);
            ImGui.TextColored(ImGuiColors.DalamudGrey3, repoText);

            ImGuiHelpers.ScaledDummy(2);

            // Description
            if (!string.IsNullOrWhiteSpace(manifest.Description))
            {
                ImGui.TextWrapped(manifest.Description);
            }

            ImGuiHelpers.ScaledDummy(5);

            var versionString = useTesting
                                    ? $"{manifest.TestingAssemblyVersion}"
                                    : $"{manifest.AssemblyVersion}";

            if (pluginManager.SafeMode)
            {
                ImGuiComponents.DisabledButton(Locs.PluginButton_SafeMode);
            }
            else if (!enableInstallButton)
            {
                ImGuiComponents.DisabledButton(Locs.PluginButton_InstallVersion(versionString));
            }
            else
            {
                using var color = ImRaii.PushColor(ImGuiCol.Button, ImGuiColors.DalamudRed.Darken(0.3f).Fade(0.4f));
                var buttonText = Locs.PluginButton_InstallVersion(versionString);
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
    }

    private void DrawAvailablePluginContextMenu(RemotePluginManifest manifest)
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var hasTestingVersionAvailable = configuration.DoPluginTest && manifest.IsAvailableForTesting;

        if (ImGui.BeginPopupContextItem("ItemContextMenu"u8))
        {
            if (hasTestingVersionAvailable)
            {
                if (ImGui.Selectable(Locs.PluginContext_InstallTestingVersion))
                {
                    EnsureHaveTestingOptIn(manifest);
                    this.StartInstall(manifest, true);
                }

                ImGui.Separator();
            }

            if (ImGui.Selectable(Locs.PluginContext_MarkAllSeen))
            {
                configuration.SeenPluginInternalName.AddRange(this.pluginListAvailable.Select(x => x.InternalName));
                configuration.QueueSave();
            }

            var isHidden = configuration.HiddenPluginInternalName.Contains(manifest.InternalName);
            switch (isHidden)
            {
                case false when ImGui.Selectable(Locs.PluginContext_HidePlugin):
                    configuration.HiddenPluginInternalName.Add(manifest.InternalName);
                    configuration.QueueSave();
                    break;
                case true when ImGui.Selectable(Locs.PluginContext_UnhidePlugin):
                    configuration.HiddenPluginInternalName.Remove(manifest.InternalName);
                    configuration.QueueSave();
                    break;
            }

            if (ImGui.Selectable(Locs.PluginContext_DeletePluginConfig))
            {
                this.ShowDeletePluginConfigWarningModal(manifest.Name).ContinueWith(t =>
                {
                    var shouldDelete = t.Result;

                    if (shouldDelete)
                    {
                        Log.Debug($"Deleting config for {manifest.InternalName}");

                        this.installStatus = OperationStatus.InProgress;

                        Task.Run(() =>
                            {
                                pluginManager.PluginConfigs.Delete(manifest.InternalName);
                                var dir = pluginManager.PluginConfigs.GetDirectory(manifest.InternalName);

                                if (Directory.Exists(dir))
                                    Directory.Delete(dir, true);
                            })
                            .ContinueWith(task =>
                            {
                                this.installStatus = OperationStatus.Idle;

                                this.DisplayErrorContinuation(task, Locs.ErrorModal_DeleteConfigFail(manifest.InternalName));
                            });
                    }
                });
            }

            ImGui.EndPopup();
        }
    }

    private void DrawInstalledPlugin(LocalPlugin plugin, int index, RemotePluginManifest? remoteManifest, AvailablePluginUpdate? availablePluginUpdate, bool showInstalled = false)
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var commandManager = Service<CommandManager>.Get();

        var testingOptIn =
            configuration.PluginTestingOptIns?.FirstOrDefault(x => x.InternalName == plugin.Manifest.InternalName);
        var trouble = false;

        // Name
        var label = plugin.Manifest.Name;

        // Testing
        if (plugin.IsTesting)
        {
            label += Locs.PluginTitleMod_TestingVersion;
        }

        var hasTestingAvailable = this.pluginListAvailable.Any(x => x.InternalName == plugin.InternalName && x.IsAvailableForTesting);
        if (hasTestingAvailable && configuration.DoPluginTest && testingOptIn == null)
        {
            label += Locs.PluginTitleMod_TestingAvailable;
        }

        // Freshly installed
        if (showInstalled)
        {
            label += Locs.PluginTitleMod_Installed;
        }

        // Disabled
        if (!plugin.IsWantedByAnyProfile || !plugin.CheckPolicy())
        {
            label += Locs.PluginTitleMod_Disabled;
            trouble = true;
        }

        // Load error
        if (plugin.State is PluginState.LoadError or PluginState.DependencyResolutionFailed && plugin.CheckPolicy()
            && !plugin.IsOutdated && !plugin.IsBanned && !plugin.IsOrphaned)
        {
            label += Locs.PluginTitleMod_LoadError;
            trouble = true;
        }

        // Unload error
        if (plugin.State == PluginState.UnloadError)
        {
            label += Locs.PluginTitleMod_UnloadError;
            trouble = true;
        }

        // Dev plugins can never update
        if (plugin.IsDev)
            availablePluginUpdate = null;

        // Update available
        if (availablePluginUpdate != null)
        {
            label += Locs.PluginTitleMod_HasUpdate;
        }

        // Freshly updated
        var thisWasUpdated = false;
        if (this.updatedPlugins != null && !plugin.IsDev)
        {
            var update = this.updatedPlugins.FirstOrDefault(update => update.InternalName == plugin.Manifest.InternalName);
            if (update != null)
            {
                if (update.Status == PluginUpdateStatus.StatusKind.Success)
                {
                    thisWasUpdated = true;
                    label += Locs.PluginTitleMod_Updated;
                }
                else
                {
                    label += Locs.PluginTitleMod_UpdateFailed;
                }
            }
        }

        // Outdated API level
        if (plugin.IsOutdated)
        {
            label += Locs.PluginTitleMod_OutdatedError;
            trouble = true;
        }

        // Banned
        if (plugin.IsBanned)
        {
            label += Locs.PluginTitleMod_BannedError;
            trouble = true;
        }

        // Out of service
        if (plugin.IsDecommissioned && !plugin.IsOrphaned)
        {
            label += Locs.PluginTitleMod_NoService;
            trouble = true;
        }

        // Scheduled for deletion
        if (plugin.Manifest.ScheduledForDeletion)
        {
            label += Locs.PluginTitleMod_ScheduledForDeletion;
        }

        ImGui.PushID($"installed{index}{plugin.Manifest.InternalName}");

        var applicableChangelog = plugin.IsTesting ? remoteManifest?.TestingChangelog : remoteManifest?.Changelog;
        var hasChangelog = !applicableChangelog.IsNullOrWhitespace();
        var didDrawApplicableChangelogInsideCollapsible = false;

        Version? availablePluginUpdateVersion = null;
        string? availableChangelog = null;
        var didDrawAvailableChangelogInsideCollapsible = false;

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

        if (this.DrawPluginCollapsingHeader(label, plugin, plugin.Manifest, flags, () => this.DrawInstalledPluginContextMenu(plugin, remoteManifest, testingOptIn), index))
        {
            if (!this.WasPluginSeen(plugin.Manifest.InternalName))
                configuration.SeenPluginInternalName.Add(plugin.Manifest.InternalName);

            var manifest = plugin.Manifest;

            ImGui.Indent();

            // Name
            ImGui.Text(manifest.Name);

            // Download count
            var downloadText = plugin.IsDev
                                   ? Locs.PluginBody_AuthorWithoutDownloadCount(manifest.Author)
                                   : manifest.DownloadCount > 0
                                       ? Locs.PluginBody_AuthorWithDownloadCount(manifest.Author, manifest.DownloadCount)
                                       : Locs.PluginBody_AuthorWithDownloadCountUnavailable(manifest.Author);

            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadText);

            var isThirdParty = plugin.IsThirdParty;

            // Installed from
            if (plugin.IsDev)
            {
                var fileText = Locs.PluginBody_DevPluginPath(plugin.DllFile.FullName);
                ImGui.TextColored(ImGuiColors.DalamudGrey3, fileText);
            }
            else
            {
                var repoText = Locs.PluginBody_Plugin3rdPartyRepo(manifest.InstalledFromUrl);
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
                ImGui.TextColored(ImGuiColors.DalamudGrey, $"WorkingPluginId: {plugin.EffectiveWorkingPluginId}");
                ImGui.TextColored(ImGuiColors.DalamudGrey, $"Command prefix: {ConsoleManagerPluginUtil.GetSanitizedNamespaceName(plugin.InternalName)}");
                ImGuiHelpers.ScaledDummy(3);
            }

            // Available commands (if loaded)
            if (plugin.IsLoaded)
            {
                var commands = commandManager.Commands
                                             .Where(cInfo =>
                                                        cInfo.Value is { ShowInHelp: true } &&
                                                        commandManager.GetHandlerAssemblyName(cInfo.Key, cInfo.Value) == plugin.Manifest.InternalName)
                                             .ToList();

                if (commands.Any())
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
                this.DrawDevPluginValidationIssues(devPlugin);
                ImGuiHelpers.ScaledDummy(5);
            }

            // Controls
            this.DrawPluginControlButton(plugin, availablePluginUpdate);
            this.DrawDevPluginButtons(plugin);
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
                if (ImGui.TreeNode(Locs.PluginBody_CurrentChangeLog(plugin.EffectiveVersion)))
                {
                    didDrawApplicableChangelogInsideCollapsible = true;
                    this.DrawInstalledPluginChangelog(applicableChangelog);
                    ImGui.TreePop();
                }
            }

            if (!availableChangelog.IsNullOrWhitespace() && ImGui.TreeNode(Locs.PluginBody_UpdateChangeLog(availablePluginUpdateVersion)))
            {
                this.DrawInstalledPluginChangelog(availableChangelog);
                ImGui.TreePop();
                didDrawAvailableChangelogInsideCollapsible = true;
            }
        }

        if (thisWasUpdated &&
            hasChangelog &&
            !didDrawApplicableChangelogInsideCollapsible)
        {
            this.DrawInstalledPluginChangelog(applicableChangelog);
        }

        if (this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.UpdateablePlugins &&
            !availableChangelog.IsNullOrWhitespace() &&
            !didDrawAvailableChangelogInsideCollapsible)
        {
            this.DrawInstalledPluginChangelog(availableChangelog);
        }

        ImGui.PopID();
    }

    private void DrawInstalledPluginChangelog(string changelog)
    {
        ImGuiHelpers.ScaledDummy(5);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, this.changelogBgColor);
        ImGui.PushStyleColor(ImGuiCol.Text, this.changelogTextColor);

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(7, 5));

        if (ImGui.BeginChild("##changelog"u8, new Vector2(-1, 100), true, ImGuiWindowFlags.NoNavFocus | ImGuiWindowFlags.NoNavInputs | ImGuiWindowFlags.AlwaysAutoResize))
        {
            ImGui.Text("Changelog:"u8);
            ImGuiHelpers.ScaledDummy(2);
            ImGui.TextWrapped(changelog!);
        }

        ImGui.EndChild();

        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
    }

    private unsafe void DrawInstalledPluginContextMenu(LocalPlugin plugin, RemotePluginManifest? remoteManifest, PluginTestingOptIn? optIn)
    {
        var pluginManager = Service<PluginManager>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        if (ImGui.BeginPopupContextItem("InstalledItemContextMenu"u8))
        {
            if (configuration.DoPluginTest)
            {
                if (remoteManifest == null || remoteManifest?.IsTestingExclusive == true)
                    ImGui.BeginDisabled();

                if (ImGui.MenuItem(Locs.PluginContext_TestingOptIn, optIn != null))
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

                if (remoteManifest?.IsTestingExclusive == true)
                    ImGui.EndDisabled();
            }

            if (ImGui.MenuItem(Locs.PluginContext_DeletePluginConfigReload))
            {
                this.ShowDeletePluginConfigWarningModal(plugin.Manifest.Name, optIn != null).ContinueWith(t =>
                {
                    var shouldDelete = t.Result;

                    if (shouldDelete)
                    {
                        Log.Debug($"Deleting config for {plugin.Manifest.InternalName}");

                        this.installStatus = OperationStatus.InProgress;

                        Task.Run(() => pluginManager.DeleteConfigurationAsync(plugin))
                            .ContinueWith(task =>
                            {
                                this.installStatus = OperationStatus.Idle;

                                this.DisplayErrorContinuation(task, Locs.ErrorModal_DeleteConfigFail(plugin.Manifest.InternalName));
                            });
                    }
                });
            }

            ImGui.EndPopup();
        }
    }

    private void DrawPluginControlButton(LocalPlugin plugin, AvailablePluginUpdate? availableUpdate)
    {
        var notifications = Service<NotificationManager>.Get();
        var pluginManager = Service<PluginManager>.Get();
        var profileManager = Service<ProfileManager>.Get();
        var config = Service<DalamudConfiguration>.Get();

        var applicableForProfiles = plugin.Manifest.SupportsProfiles /*&& !plugin.IsDev*/;
        var profilesThatWantThisPlugin = profileManager.Profiles
                                                       .Where(x => x.WantsPlugin(plugin.EffectiveWorkingPluginId) != null)
                                                       .ToArray();
        var isInSingleProfile = profilesThatWantThisPlugin.Length == 1;
        var isDefaultPlugin = profileManager.IsInDefaultProfile(plugin.EffectiveWorkingPluginId);

        // Disable everything if the updater is running or another plugin is operating
        var disabled = this.updateStatus == OperationStatus.InProgress || this.installStatus == OperationStatus.InProgress;

        // Disable everything if the plugin is outdated
        disabled = disabled || (plugin.IsOutdated && !pluginManager.LoadAllApiLevels && !plugin.IsDev) || plugin.IsBanned;

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

        var toggleId = plugin.Manifest.InternalName;
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
                            .ContinueWith(this.DisplayErrorContinuation, Locs.Profiles_CouldNotAdd);
                    }
                    else
                    {
                        Task.Run(() => profile.RemoveAsync(plugin.EffectiveWorkingPluginId))
                            .ContinueWith(this.DisplayErrorContinuation, Locs.Profiles_CouldNotRemove);
                    }
                }

                ImGui.SameLine();

                ImGui.Text(profile.Name);

                didAny = true;
            }

            if (!didAny)
                ImGui.TextColored(ImGuiColors.DalamudGrey, Locs.Profiles_None);

            ImGui.Separator();

            if (ImGuiComponents.IconButton(FontAwesomeIcon.Times))
            {
                // TODO: Work this out
                Task.Run(() => profileManager.DefaultProfile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, plugin.IsLoaded, false))
                    .GetAwaiter().GetResult();
                foreach (var profile in profileManager.Profiles.Where(x => !x.IsDefaultProfile && x.Plugins.Any(y => y.InternalName == plugin.Manifest.InternalName)))
                {
                    Task.Run(() => profile.RemoveAsync(plugin.EffectiveWorkingPluginId, false))
                        .GetAwaiter().GetResult();
                }

                Task.Run(() => profileManager.ApplyAllWantStatesAsync("Remove from profile"))
                    .ContinueWith(this.DisplayErrorContinuation, Locs.ErrorModal_ProfileApplyFail);
            }

            ImGui.SameLine();
            ImGui.Text(Locs.Profiles_RemoveFromAll);

            ImGui.EndPopup();
        }

        var inMultipleProfiles = !isDefaultPlugin && !isInSingleProfile;
        var inSingleNonDefaultProfileWhichIsDisabled =
            isInSingleProfile && !profilesThatWantThisPlugin.First().IsEnabled;
        var inSingleNonDefaultProfileWhichDoesNotWantActive =
            isInSingleProfile && !profilesThatWantThisPlugin.First().CheckWantsActiveFromGameState(Service<PlayerState>.Get().ContentId);

        if (plugin.State is PluginState.UnloadError or PluginState.LoadError or PluginState.DependencyResolutionFailed && !plugin.IsDev && !plugin.IsOutdated)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, false);

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_LoadUnloadFailed);
        }
        else if (this.enableDisableStatus == OperationStatus.InProgress && this.enableDisableWorkingPluginId == plugin.EffectiveWorkingPluginId)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, this.loadingIndicatorKind == LoadingIndicatorKind.EnablingSingle);
        }
        else if (disabled || inMultipleProfiles || inSingleNonDefaultProfileWhichIsDisabled || inSingleNonDefaultProfileWhichDoesNotWantActive || pluginManager.SafeMode)
        {
            ImGuiComponents.DisabledToggleButton(toggleId, isLoadedAndUnloadable);

            if (pluginManager.SafeMode && ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_SafeMode);
            else if (inMultipleProfiles && ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_NeedsToBeInSingleProfile);
            else if (inSingleNonDefaultProfileWhichIsDisabled && ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_SingleProfileDisabled(profilesThatWantThisPlugin.First().Name));
            else if (inSingleNonDefaultProfileWhichDoesNotWantActive && ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_SingleProfileDoesNotWantActive(profilesThatWantThisPlugin.First().Name));
        }
        else
        {
            if (ImGuiComponents.ToggleButton(toggleId, ref isLoadedAndUnloadable))
            {
                var applicableProfile = profilesThatWantThisPlugin.First();
                Log.Verbose("Switching {InternalName} in {Profile} to {State}",
                            plugin.InternalName, applicableProfile, isLoadedAndUnloadable);

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
                    this.enableDisableStatus = OperationStatus.InProgress;
                    this.loadingIndicatorKind = LoadingIndicatorKind.DisablingSingle;
                    this.enableDisableWorkingPluginId = plugin.EffectiveWorkingPluginId;

                    Task.Run(async () =>
                    {
                        await plugin.UnloadAsync();
                        await applicableProfile.AddOrUpdateAsync(
                            plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, false, false);

                        notifications.AddNotification(Locs.Notifications_PluginDisabled(plugin.Manifest.Name), Locs.Notifications_PluginDisabledTitle, NotificationType.Success);
                    }).ContinueWith(t =>
                    {
                        this.enableDisableStatus = OperationStatus.Complete;
                        this.DisplayErrorContinuation(t, Locs.ErrorModal_UnloadFail(plugin.Name));
                    });
                }
                else
                {
                    async Task Enabler()
                    {
                        this.enableDisableStatus = OperationStatus.InProgress;
                        this.loadingIndicatorKind = LoadingIndicatorKind.EnablingSingle;
                        this.enableDisableWorkingPluginId = plugin.EffectiveWorkingPluginId;

                        await applicableProfile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false);
                        await plugin.LoadAsync(PluginLoadReason.Installer);

                        notifications.AddNotification(Locs.Notifications_PluginEnabled(plugin.Manifest.Name), Locs.Notifications_PluginEnabledTitle, NotificationType.Success);
                    }

                    var continuation = (Task t) =>
                    {
                        this.enableDisableStatus = OperationStatus.Complete;
                        this.DisplayErrorContinuation(t, Locs.ErrorModal_LoadFail(plugin.Name));
                    };

                    if (availableUpdate != default && !availableUpdate.InstalledPlugin.IsDev)
                    {
                        this.ShowUpdateModal(plugin).ContinueWith(async t =>
                        {
                            var shouldUpdate = t.Result;

                            if (shouldUpdate)
                            {
                                // We need to update the profile right here, because PM will not enable the plugin otherwise
                                await applicableProfile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false);
                                await this.UpdateSinglePlugin(availableUpdate);
                            }
                            else
                            {
                                _ = Task.Run(Enabler).ContinueWith(continuation);
                            }
                        });
                    }
                    else
                    {
                        _ = Task.Run(Enabler).ContinueWith(continuation);
                    }
                }
            }
        }

        // StyleModelV1.DalamudStandard.Pop();

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(15, 0);

        if (plugin.State == PluginState.Loaded)
        {
            // Only if the plugin isn't broken.
            this.DrawOpenPluginSettingsButton(plugin);

            ImGui.SameLine();
            ImGuiHelpers.ScaledDummy(5, 0);
        }

        if (applicableForProfiles && config.ProfilesEnabled)
        {
            ImGui.SameLine();
            if (ImGuiComponents.IconButton(FontAwesomeIcon.Toolbox))
            {
                ImGui.OpenPopup(profileChooserPopupName);
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_PickProfiles);
        }
        else if (!applicableForProfiles && config.ProfilesEnabled)
        {
            ImGui.SameLine();

            ImGui.BeginDisabled();
            ImGuiComponents.IconButton(FontAwesomeIcon.Toolbox);
            ImGui.EndDisabled();

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_ProfilesNotSupported);
        }
    }

    private async Task<bool> UpdateSinglePlugin(AvailablePluginUpdate update)
    {
        var pluginManager = Service<PluginManager>.Get();

        this.installStatus = OperationStatus.InProgress;
        this.loadingIndicatorKind = LoadingIndicatorKind.UpdatingSingle;

        return await Task.Run(async () => await pluginManager.UpdateSinglePluginAsync(update, true, false))
                         .ContinueWith(task =>
                         {
                             // There is no need to set as Complete for an individual plugin installation
                             this.installStatus = OperationStatus.Idle;

                             if (task.IsCompletedSuccessfully &&
                                 task.Result.Status != PluginUpdateStatus.StatusKind.Success)
                             {
                                 this.ShowErrorModal(
                                     Locs.ErrorModal_SingleUpdateFail(update.UpdateManifest.Name, PluginUpdateStatus.LocalizeUpdateStatusKind(task.Result.Status)));
                                 return false;
                             }

                             return this.DisplayErrorContinuation(task, Locs.ErrorModal_SingleUpdateFail(update.UpdateManifest.Name, "Exception"));
                         });
    }

    private void DrawUpdateSinglePluginButton(AvailablePluginUpdate update)
    {
        if (ImGuiComponents.IconButton(FontAwesomeIcon.Download))
        {
            Task.Run(() => this.UpdateSinglePlugin(update));
        }

        if (ImGui.IsItemHovered())
        {
            var updateVersion = update.UseTesting
                                    ? update.UpdateManifest.TestingAssemblyVersion
                                    : update.UpdateManifest.AssemblyVersion;
            ImGui.SetTooltip(Locs.PluginButtonToolTip_UpdateSingle(updateVersion.ToString()));
        }
    }

    private void DrawOpenPluginSettingsButton(LocalPlugin plugin)
    {
        var hasMainUi = plugin.DalamudInterface?.LocalUiBuilder.HasMainUi ?? false;
        var hasConfig = plugin.DalamudInterface?.LocalUiBuilder.HasConfigUi ?? false;
        if (hasMainUi)
        {
            ImGui.SameLine();
            if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.ArrowUpRightFromSquare, Locs.PluginButton_OpenUi))
            {
                try
                {
                    plugin.DalamudInterface.LocalUiBuilder.OpenMain();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, $"Error during OpenMain(): {plugin.Name}");
                }
            }

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip(Locs.PluginButtonToolTip_OpenUi);
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
            if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Cog, Locs.PluginButton_OpenSettings))
            {
                try
                {
                    plugin.DalamudInterface.LocalUiBuilder.OpenConfig();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, $"Error during OpenConfig: {plugin.Name}");
                }
            }

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip(Locs.PluginButtonToolTip_OpenConfiguration);
            }
        }
    }

    private void DrawSendFeedbackButton(RemotePluginManifest manifest, bool isTesting, bool big)
    {
        var clicked = big ?
                          ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Comment, Locs.FeedbackModal_Title) :
                          ImGuiComponents.IconButton(FontAwesomeIcon.Comment);

        if (clicked)
        {
            this.feedbackPlugin = manifest;
            this.feedbackModalOnNextFrame = true;
            this.feedbackIsTesting = isTesting;
        }

        if (ImGui.IsItemHovered())
        {
            ImGui.SetTooltip(Locs.FeedbackModal_Title);
        }
    }

    private void DrawDevPluginValidationIssues(LocalDevPlugin devPlugin)
    {
        if (!devPlugin.IsLoaded)
        {
            ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "You have to load this plugin to see validation issues."u8);
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
                ImGui.TextColoredWrapped(ImGuiColors.SuccessForeground, "No validation issues found in this plugin!"u8);
            }
            else
            {
                var numValidProblems = problems.Count(
                    problem => devPlugin.DismissedValidationProblems.All(name => name != problem.GetType().Name));
                var shouldBother = numValidProblems > 0;
                var validationIssuesText = shouldBother ?
                    $"Found {problems.Count} validation issue{(problems.Count > 1 ? "s" : string.Empty)} in this plugin!" :
                    $"{problems.Count} dismissed validation issue{(problems.Count > 1 ? "s" : string.Empty)} in this plugin.";

                using var col = ImRaii.PushColor(ImGuiCol.Text, shouldBother ? ImGuiColors.WarningForeground : ImGuiColors.DalamudGrey);
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
                                if (ImGuiComponents.IconButton(
                                        $"##dismissValidationIssue{problem.GetType().Name}",
                                        FontAwesomeIcon.TimesCircle))
                                {
                                    devPlugin.DismissedValidationProblems.Add(problem.GetType().Name);
                                    Service<DalamudConfiguration>.Get().QueueSave();
                                }

                                if (ImGui.IsItemHovered())
                                {
                                    ImGui.SetTooltip("Dismiss this issue"u8);
                                }
                            }

                            ImGui.SameLine();
                        }

                        var iconColor = problem.Severity switch
                        {
                            PluginValidator.ValidationSeverity.Fatal => ImGuiColors.ErrorForeground,
                            PluginValidator.ValidationSeverity.Warning => ImGuiColors.WarningForeground,
                            PluginValidator.ValidationSeverity.Information => ImGuiColors.InfoForeground,
                            _ => ImGuiColors.DalamudGrey,
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
                                    throw new ArgumentOutOfRangeException();
                            }
                        }

                        ImGui.SameLine();

                        using (ImRaii.PushColor(ImGuiCol.Text, thisProblemIsDismissed ? ImGuiColors.DalamudGrey : ImGuiColors.DalamudWhite))
                        {
                            ImGui.TextWrapped(problem.GetLocalizedDescription());
                        }
                    }
                }
            }
        }
    }

    private void DrawDevPluginButtons(LocalPlugin localPlugin)
    {
        ImGui.SameLine();

        var configuration = Service<DalamudConfiguration>.Get();

        if (localPlugin is LocalDevPlugin plugin)
        {
            var isInDefaultProfile =
                Service<ProfileManager>.Get().IsInDefaultProfile(localPlugin.EffectiveWorkingPluginId);

            // https://colorswall.com/palette/2868/
            var greenColor = new Vector4(0x5C, 0xB8, 0x5C, 0xFF) / 0xFF;
            var redColor = new Vector4(0xD9, 0x53, 0x4F, 0xFF) / 0xFF;

            // Load on boot
            using (ImRaii.Disabled(!isInDefaultProfile))
            {
                ImGui.PushStyleColor(ImGuiCol.Button, plugin.StartOnBoot ? greenColor : redColor);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, plugin.StartOnBoot ? greenColor : redColor);

                ImGui.SameLine();
                if (ImGuiComponents.IconButton(FontAwesomeIcon.PowerOff))
                {
                    plugin.StartOnBoot ^= true;
                    configuration.QueueSave();
                }

                ImGui.PopStyleColor(2);

                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip(isInDefaultProfile ? Locs.PluginButtonToolTip_StartOnBoot : Locs.PluginButtonToolTip_NeedsToBeInDefault);
                }
            }

            // Automatic reload
            ImGui.PushStyleColor(ImGuiCol.Button, plugin.AutomaticReload ? greenColor : redColor);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, plugin.AutomaticReload ? greenColor : redColor);

            ImGui.SameLine();
            if (ImGuiComponents.IconButton(FontAwesomeIcon.SyncAlt))
            {
                plugin.AutomaticReload ^= true;
                configuration.QueueSave();
            }

            ImGui.PopStyleColor(2);

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip(Locs.PluginButtonToolTip_AutomaticReloading);
            }

            // Error Notifications
            ImGui.PushStyleColor(ImGuiCol.Button, plugin.NotifyForErrors ? greenColor : redColor);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, plugin.NotifyForErrors ? greenColor : redColor);

            ImGui.SameLine();
            if (ImGuiComponents.IconButton(FontAwesomeIcon.Bolt))
            {
                plugin.NotifyForErrors ^= true;
                configuration.QueueSave();
            }

            ImGui.PopStyleColor(2);

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip(Locs.PluginButtonToolTip_NotifyForErrors);
            }
        }
    }

    private void DrawDeletePluginButton(LocalPlugin plugin)
    {
        /*var unloaded = plugin.State == PluginState.Unloaded || plugin.State == PluginState.LoadError;

        // When policy check fails, the plugin is never loaded
        var showButton = unloaded && (plugin.IsDev || plugin.IsOutdated || plugin.IsBanned || plugin.IsOrphaned || !plugin.CheckPolicy());

        if (!showButton)
            return;*/

        var pluginManager = Service<PluginManager>.Get();
        
        ImGui.SameLine();
        if (plugin.State == PluginState.Loaded)
        {
            ImGui.PushFont(InterfaceManager.IconFont);
            ImGuiComponents.DisabledButton(FontAwesomeIcon.TrashAlt.ToIconString());
            ImGui.PopFont();

            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip(plugin.State == PluginState.Loaded
                                     ? Locs.PluginButtonToolTip_DeletePluginLoaded
                                     : Locs.PluginButtonToolTip_DeletePluginRestricted);
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
                    
                    pluginManager.RemovePlugin(plugin);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, $"Plugin installer threw an error during removal of {plugin.Name}");

                    this.ShowErrorModal(Locs.ErrorModal_DeleteFail(plugin.Name));
                }
            }

            if (ImGui.IsItemHovered())
            {
                string tooltipMessage;
                if (plugin.Manifest.ScheduledForDeletion)
                {
                    tooltipMessage = Locs.PluginButtonToolTip_DeletePluginScheduledCancel;
                }
                else if (plugin.State is PluginState.Unloaded or PluginState.DependencyResolutionFailed)
                {
                    tooltipMessage = Locs.PluginButtonToolTip_DeletePlugin;
                }
                else
                {
                    tooltipMessage = Locs.PluginButtonToolTip_DeletePluginScheduled;
                }

                ImGui.SetTooltip(tooltipMessage);
            }
        }
    }

    private bool DrawVisitRepoUrlButton(string? repoUrl, bool big)
    {
        if (!string.IsNullOrEmpty(repoUrl) && repoUrl.StartsWith("https://"))
        {
            ImGui.SameLine();

            var clicked = big ?
                              ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Globe, "Open website") :
                              ImGuiComponents.IconButton(FontAwesomeIcon.Globe);
            if (clicked)
            {
                try
                {
                    _ = Process.Start(new ProcessStartInfo()
                    {
                        FileName = repoUrl,
                        UseShellExecute = true,
                    });
                }
                catch (Exception ex)
                {
                    Log.Error(ex, $"Could not open repoUrl: {repoUrl}");
                }
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(Locs.PluginButtonToolTip_VisitPluginUrl);

            return true;
        }

        return false;
    }

    private bool DrawPluginImages(LocalPlugin? plugin, IPluginManifest manifest, bool isThirdParty, int index)
    {
        var hasImages = this.imageCache.TryGetImages(plugin, manifest, isThirdParty, out var imageTextures);
        if (!hasImages || imageTextures.All(x => x == null))
            return false;

        const float thumbFactor = 2.7f;

        var scrollBarSize = 15;
        ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, scrollBarSize);
        ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, Vector4.Zero);

        var width = ImGui.GetWindowWidth();

        if (ImGui.BeginChild($"plugin{index}ImageScrolling", new Vector2(width - (70 * ImGuiHelpers.GlobalScale), (PluginImageCache.PluginImageHeight / thumbFactor) + scrollBarSize), false, ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse | ImGuiWindowFlags.NoBackground))
        {
            for (var i = 0; i < imageTextures.Length; i++)
            {
                var image = imageTextures[i];
                if (image == null)
                    continue;

                ImGui.PushStyleVar(ImGuiStyleVar.PopupBorderSize, 0);
                ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Vector2.Zero);
                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                var popupId = $"plugin{index}image{i}";
                if (ImGui.BeginPopup(popupId))
                {
                    if (ImGui.ImageButton(image.Handle, new Vector2(image.Width, image.Height)))
                        ImGui.CloseCurrentPopup();

                    ImGui.EndPopup();
                }

                ImGui.PopStyleVar(3);

                ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);

                float xAct = image.Width;
                float yAct = image.Height;
                float xMax = PluginImageCache.PluginImageWidth;
                float yMax = PluginImageCache.PluginImageHeight;

                // scale image if undersized
                if (xAct < xMax && yAct < yMax)
                {
                    var scale = Math.Min(xMax / xAct, yMax / yAct);
                    xAct *= scale;
                    yAct *= scale;
                }

                var size = ImGuiHelpers.ScaledVector2(xAct / thumbFactor, yAct / thumbFactor);
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

    private bool IsManifestFiltered(IPluginManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(this.searchText))
            return false;

        return GetManifestSearchScore(manifest) < 100;
    }

    private int GetManifestSearchScore(IPluginManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(this.searchText))
            return 0;

        var searchQuery = this.searchText.Trim().ToLowerInvariant();
        var searchTerms = searchQuery.Split([' ', '　'], StringSplitOptions.RemoveEmptyEntries);

        if (searchTerms.Length == 0) return 0;

        var totalScore = 0;

        totalScore += CalculateMatchScore(searchTerms, manifest.Name,         weight: 200);
        totalScore += CalculateMatchScore(searchTerms, manifest.InternalName, weight: 180);
        totalScore += CalculateMatchScore(searchTerms, manifest.Author,       weight: 150);
        totalScore += CalculateMatchScore(searchTerms, manifest.Punchline,    weight: 120);
        totalScore += CalculateMatchScore(searchTerms, manifest.Description,  weight: 100);

        if (manifest.Tags != null)
        {
            foreach (var tag in manifest.Tags)
                totalScore += CalculateMatchScore(searchTerms, tag,  weight: 100);
        }
        
        if (totalScore == 0) return -100;
        return totalScore;
    }

    private int CalculateMatchScore(string[] searchTerms, string? target, int weight)
    {
        if (string.IsNullOrWhiteSpace(target))
            return 0;

        var targetLower = target.Trim().ToLowerInvariant();
        var score = 0;

        foreach (var term in searchTerms)
        {
            if (term.Length < 2) continue; // 忽略过短的搜索词
            
            if (targetLower.Equals(term))
                score += weight * 2;
            else if (targetLower.StartsWith(term, StringComparison.OrdinalIgnoreCase) ||
                     targetLower.Contains(" " + term, StringComparison.OrdinalIgnoreCase))
                score += (int)(weight * 1.5);
            else if (targetLower.Contains(term, StringComparison.OrdinalIgnoreCase))
                score += weight;
                
            if (IsChinese(term) && targetLower.Contains(term))
                score += (int)(weight * 1.3);
        }

        foreach (var term in searchTerms.Where(t => t.Length >= 4))
        {
            if (targetLower.Contains(term))
                score += 50;
        }

        return score;
    }
    
    private static bool IsChinese(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        foreach (var rune in input.EnumerateRunes())
        {
            if (!IsChineseRune(rune))
                return false;
        }

        return true;
        
        static bool IsChineseRune(Rune rune)
        {
            var value = (uint)rune.Value;

            return value - 0x4E00u  <= 0x9FFFu  - 0x4E00u  ||
                   value - 0x3400u  <= 0x4DBFu  - 0x3400u  ||
                   value - 0x20000u <= 0x2FA1Fu - 0x20000u ||
                   value - 0x30000u <= 0x323AFu - 0x30000u ||
                   value - 0xF900u  <= 0xFAFFu  - 0xF900u;
        }
    }

    private (bool IsInstalled, LocalPlugin Plugin) IsManifestInstalled(IPluginManifest? manifest)
    {
        if (manifest == null) return (false, default);

        var plugin = this.pluginListInstalled.FirstOrDefault(plugin => plugin.Manifest.InternalName == manifest.InternalName);
        var isInstalled = plugin != default;

        return (isInstalled, plugin);
    }

    private void OnAvailablePluginsChanged()
    {
        var pluginManager = Service<PluginManager>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        lock (this.listLock)
        {
            // By removing installed plugins only when the available plugin list changes (basically when the window is
            // opened), plugins that have been newly installed remain in the available plugin list as installed.
            this.pluginListAvailable = pluginManager.AvailablePlugins.ToList();
            this.pluginListUpdatable = pluginManager.UpdatablePlugins.ToList();
            this.ResortPlugins();
        }

        this.hasHiddenPlugins = this.pluginListAvailable.Any(x => configuration.HiddenPluginInternalName.Contains(x.InternalName));

        this.UpdateCategoriesOnPluginsChange();
    }

    private void OnInstalledPluginsChanged()
    {
        var pluginManager = Service<PluginManager>.Get();
        using var pmLock = pluginManager.GetSyncScope();

        lock (this.listLock)
        {
            this.pluginListInstalled = pluginManager.InstalledPlugins.ToList();
            this.pluginListUpdatable = pluginManager.UpdatablePlugins.ToList();
            this.hasDevPlugins = this.pluginListInstalled.Any(plugin => plugin.IsDev);
            this.ResortPlugins();
        }

        this.UpdateCategoriesOnPluginsChange();
    }

    private void ResortPlugins()
    {
        switch (this.sortKind)
        {
            case PluginSortKind.Alphabetical:
                this.pluginListAvailable.Sort((p1, p2) => p1.Name.CompareTo(p2.Name));
                this.pluginListInstalled.Sort((p1, p2) => p1.Manifest.Name.CompareTo(p2.Manifest.Name));
                break;
            case PluginSortKind.DownloadCount:
                this.pluginListAvailable.Sort((p1, p2) => p2.DownloadCount.CompareTo(p1.DownloadCount));
                this.pluginListInstalled.Sort((p1, p2) => p2.Manifest.DownloadCount.CompareTo(p1.Manifest.DownloadCount));
                break;
            case PluginSortKind.LastUpdate:
                this.pluginListAvailable.Sort((p1, p2) => p2.LastUpdate.CompareTo(p1.LastUpdate));
                this.pluginListInstalled.Sort((p1, p2) =>
                {
                    // We need to get remote manifests here, as the local manifests will have the time when the current version is installed,
                    // not the actual time of the last update, as the plugin may be pending an update
                    IPluginManifest? p2Considered = this.pluginListAvailable.FirstOrDefault(x => x.InternalName == p2.InternalName);
                    p2Considered ??= p2.Manifest;

                    IPluginManifest? p1Considered = this.pluginListAvailable.FirstOrDefault(x => x.InternalName == p1.InternalName);
                    p1Considered ??= p1.Manifest;

                    return p2Considered.LastUpdate.CompareTo(p1Considered.LastUpdate);
                });
                break;
            case PluginSortKind.NewOrNot:
                this.pluginListAvailable.Sort((p1, p2) => this.WasPluginSeen(p1.InternalName)
                                                              .CompareTo(this.WasPluginSeen(p2.InternalName)));
                this.pluginListInstalled.Sort((p1, p2) => this.WasPluginSeen(p1.Manifest.InternalName)
                                                              .CompareTo(this.WasPluginSeen(p2.Manifest.InternalName)));
                break;
            case PluginSortKind.NotInstalled:
                this.pluginListAvailable.Sort((p1, p2) => this.pluginListInstalled.Any(x => x.Manifest.InternalName == p1.InternalName)
                                                              .CompareTo(this.pluginListInstalled.Any(x => x.Manifest.InternalName == p2.InternalName)));
                this.pluginListInstalled.Sort((p1, p2) => p1.Manifest.Name.CompareTo(p2.Manifest.Name)); // Makes no sense for installed plugins
                break;
            case PluginSortKind.EnabledDisabled:
                this.pluginListAvailable.Sort((p1, p2) =>
                {
                    bool IsEnabled(PluginManifest manifest)
                    {
                        return this.pluginListInstalled.Any(x => x.Manifest.InternalName == manifest.InternalName);
                    }

                    return IsEnabled(p2).CompareTo(IsEnabled(p1));
                });
                this.pluginListInstalled.Sort((p1, p2) => (p2.State == PluginState.Loaded).CompareTo(p1.State == PluginState.Loaded));
                break;
            case PluginSortKind.ProfileOrNot:
                this.pluginListAvailable.Sort((p1, p2) => p1.Name.CompareTo(p2.Name));

                var profman = Service<ProfileManager>.Get();
                this.pluginListInstalled.Sort((p1, p2) => profman.IsInDefaultProfile(p1.EffectiveWorkingPluginId).CompareTo(profman.IsInDefaultProfile(p2.EffectiveWorkingPluginId)));
                break;
            case PluginSortKind.SearchScore:
                this.pluginListAvailable = this.pluginListAvailable.OrderByDescending(this.GetManifestSearchScore).ThenBy(m => m.Name).ToList();
                this.pluginListInstalled = this.pluginListInstalled.OrderByDescending(p => this.GetManifestSearchScore(p.Manifest)).ThenBy(m => m.Name).ToList();
                break;
            default:
                throw new InvalidEnumArgumentException("Unknown plugin sort type.");
        }
    }

    private bool WasPluginSeen(string internalName) =>
        Service<DalamudConfiguration>.Get().SeenPluginInternalName.Contains(internalName);

    private Task ShowErrorModal(string message)
    {
        this.errorModalMessage = message;
        this.errorModalDrawing = true;
        this.errorModalOnNextFrame = true;
        this.errorModalTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return this.errorModalTaskCompletionSource.Task;
    }

    private Task<bool> ShowUpdateModal(LocalPlugin plugin)
    {
        this.updateModalOnNextFrame = true;
        this.updateModalPlugin = plugin;
        this.updateModalTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return this.updateModalTaskCompletionSource.Task;
    }

    private void UpdateCategoriesOnSearchChange(string? previousSearchText)
    {
        if (string.IsNullOrEmpty(this.searchText))
        {
            this.categoryManager.SetCategoryHighlightsForPlugins(Array.Empty<RemotePluginManifest>());

            // Reset here for good measure, as we're returning from a search
            this.openPluginCollapsibles.Clear();
        }
        else
        {
            var pluginsMatchingSearch = this.pluginListAvailable.Where(rm => !this.IsManifestFiltered(rm)).ToArray();

            // Check if the search results are different, and clear the open collapsibles if they are
            if (previousSearchText != null)
            {
                var previousSearchResults = this.pluginListAvailable.Where(rm => !this.IsManifestFiltered(rm)).ToArray();
                if (!previousSearchResults.SequenceEqual(pluginsMatchingSearch))
                    this.openPluginCollapsibles.Clear();
            }

            this.categoryManager.SetCategoryHighlightsForPlugins(pluginsMatchingSearch);
        }
    }

    private void UpdateCategoriesOnPluginsChange()
    {
        this.categoryManager.BuildCategories(this.pluginListAvailable);
        this.UpdateCategoriesOnSearchChange(null);
    }

    private void DrawFontawesomeIconOutlined(FontAwesomeIcon icon, Vector4 outline, Vector4 iconColor)
    {
        var positionOffset = ImGuiHelpers.ScaledVector2(0.0f, 1.0f);
        var cursorStart = ImGui.GetCursorPos() + positionOffset;
        ImGui.PushFont(InterfaceManager.IconFont);

        ImGui.PushStyleColor(ImGuiCol.Text, outline);
        foreach (var x in Enumerable.Range(-1, 3))
        {
            foreach (var y in Enumerable.Range(-1, 3))
            {
                if (x is 0 && y is 0) continue;

                ImGui.SetCursorPos(cursorStart + new Vector2(x, y));
                ImGui.Text(icon.ToIconString());
            }
        }

        ImGui.PopStyleColor();

        ImGui.PushStyleColor(ImGuiCol.Text, iconColor);
        ImGui.SetCursorPos(cursorStart);
        ImGui.Text(icon.ToIconString());
        ImGui.PopStyleColor();

        ImGui.PopFont();

        ImGui.SetCursorPos(ImGui.GetCursorPos() - positionOffset);
    }

    // Animates a tooltip when hovering over the ImGui Item before this call.
    private void VerifiedCheckmarkFadeTooltip(string source, string tooltip)
    {
        const float fadeInStartDelay = 250.0f;

        var isHoveringSameItem = this.verifiedCheckmarkHoveredPlugin == source;

        // If we just started a hover, start the timer
        if (ImGui.IsItemHovered() && !this.tooltipFadeInStopwatch.IsRunning)
        {
            this.verifiedCheckmarkHoveredPlugin = source;
            this.tooltipFadeInStopwatch.Restart();
        }

        // If we were last hovering this plugins item and are no longer hovered over that item, reset the timer
        if (!ImGui.IsItemHovered() && isHoveringSameItem)
        {
            this.verifiedCheckmarkHoveredPlugin = string.Empty;
            this.tooltipFadeInStopwatch.Stop();
            this.tooltipFadeEasing.Reset();
        }

        // If we have been hovering this item for > fadeInStartDelay milliseconds, fade in tooltip over fadeInTime milliseconds
        if (ImGui.IsItemHovered() && isHoveringSameItem && this.tooltipFadeInStopwatch.ElapsedMilliseconds >= fadeInStartDelay)
        {
            if (!this.tooltipFadeEasing.IsRunning)
                this.tooltipFadeEasing.Start();

            this.tooltipFadeEasing.Update();
            var fadePercent = this.tooltipFadeEasing.EasedPoint.X;
            ImGui.PushStyleColor(ImGuiCol.Text, ImGui.GetStyle().Colors[(int)ImGuiCol.Text] with { W = fadePercent });
            ImGui.PushStyleColor(ImGuiCol.FrameBg, ImGui.GetStyle().Colors[(int)ImGuiCol.FrameBg] with { W = fadePercent });
            ImGui.SetTooltip(tooltip);
            ImGui.PopStyleColor(2);
        }
    }

    [SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1201:Elements should appear in the correct order", Justification = "Disregard here")]
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:Elements should be documented", Justification = "Locs")]
    internal static class Locs
    {
        #region Window Title
        public static string WindowTitle => "插件安装器";
        public static string WindowTitleMod_Testing => " (测试版)";
        #endregion

        #region Header
        public static string Header_Hint => "此窗口用于安装和移除 Dalamud 插件。\n这些插件由社区制作。";
        public static string Header_SearchPlaceholder => "搜索";
        #endregion

        #region SortBy
        public static string SortBy_SearchScore => "搜索权重";
        public static string SortBy_Alphabetical => "按字母顺序";
        public static string SortBy_DownloadCounts => "下载次数";
        public static string SortBy_LastUpdate => "最后更新";
        public static string SortBy_NewOrNot => "新插件优先";
        public static string SortBy_NotInstalled => "未安装优先";
        public static string SortBy_EnabledDisabled => "已启用/已禁用";
        public static string SortBy_ProfileOrNot => "在合集中";
        public static string SortBy_Label => "排序方式";
        #endregion

        #region Tab body

        public static string TabBody_LoadingPlugins => Loc.Localize("InstallerLoading", "Loading plugins...");

        public static string TabBody_DownloadFailed => Loc.Localize("InstallerDownloadFailed", "Download failed.");

        public static string TabBody_SafeMode => Loc.Localize("InstallerSafeMode", "Dalamud is running in Plugin Safe Mode, restart to activate plugins.");

        public static string TabBody_NoPluginsTesting => Loc.Localize("InstallerNoPluginsTesting", "You aren't testing any plugins at the moment!\nYou can opt in to testing versions in the plugin context menu.");

        public static string TabBody_NoPluginsInstalled =>
            string.Format(Loc.Localize("InstallerNoPluginsInstalled", "You don't have any plugins installed yet!\nYou can install them from the \"{0}\" tab."), PluginCategoryManager.Locs.Category_All);

        public static string TabBody_NoPluginsAvailable => Loc.Localize("InstallerNoPluginsAvailable", "No plugins are available at the moment.");

        public static string TabBody_NoPluginsUpdateable => Loc.Localize("InstallerNoPluginsUpdate", "No plugins have updates available at the moment.");

        public static string TabBody_NoPluginsDev => Loc.Localize("InstallerNoPluginsDev", "You don't have any dev plugins. Add them from the settings.");

        public static string TabBody_NoPluginsEnabled => Loc.Localize("InstallerNoPluginsEnabled", "You don't have any enabled plugins.");

        public static string TabBody_NoPluginsDisabled => Loc.Localize("InstallerNoPluginsDisabled", "You don't have any disabled plugins.");

        public static string TabBody_NoPluginsIncompatible => Loc.Localize("InstallerNoPluginsIncompatible", "You don't have any incompatible plugins.");

        #endregion

        #region Search text
        public static string TabBody_SearchNoMatching => "未找到符合搜索条件的插件。";
        public static string TabBody_SearchNoCompatible => "未找到兼容的插件。请重启游戏并重试。";
        public static string TabBody_SearchNoInstalled => "当前没有安装任何插件。可从\"所有插件\"标签页安装。";
        public static string TabBody_NoMoreResultsFor(string query) => "无更多有关 \"{0}\" 的搜索结果".Format(query);
        public static string TabBody_ChangelogNone => "已安装的插件均无更新日志。";
        public static string TabBody_ChangelogError => "无法下载更新日志。";
        #endregion

        #region Plugin title text
        public static string PluginTitleMod_Installed => " (已安装)";
        public static string PluginTitleMod_Disabled => " (已禁用)";
        public static string PluginTitleMod_NoService => " (已过时)";
        public static string PluginTitleMod_Unloaded => " (已卸载)";
        public static string PluginTitleMod_HasUpdate => " (可更新)";
        public static string PluginTitleMod_Updated => " (已更新)";
        public static string PluginTitleMod_TestingVersion => " (测试版)";
        public static string PluginTitleMod_TestingExclusive => " (仅限测试版)";
        public static string PluginTitleMod_TestingAvailable => " (存在测试版)";
        public static string PluginTitleMod_DevPlugin => " (开发版)";
        public static string PluginTitleMod_Incompatible => " (不兼容)";
        public static string PluginTitleMod_UpdateFailed => " (更新失败)";
        public static string PluginTitleMod_LoadError => " (加载失败)";
        public static string PluginTitleMod_UnloadError => " (卸载错误)";
        public static string PluginTitleMod_OutdatedError => " (API 版本不对应)";
        public static string PluginTitleMod_BannedError => " (自动禁用)";
        public static string PluginTitleMod_OrphanedError => " (未知仓库)";
        public static string PluginTitleMod_ScheduledForDeletion => " (计划删除)";
        public static string PluginTitleMod_New => " 新插件!";
        #endregion

        #region Plugin context menu
        public static string PluginContext_TestingOptIn => "接收插件测试版";
        public static string PluginContext_InstallTestingVersion => "安装测试版";
        public static string PluginContext_MarkAllSeen => "标记所有为已查看";
        public static string PluginContext_HidePlugin => "从安装器中隐藏";
        public static string PluginContext_UnhidePlugin => "在安装器中显示";
        public static string PluginContext_DeletePluginConfig => "重置插件数据";
        public static string PluginContext_DeletePluginConfigReload => "重置插件数据并重新加载";
        #endregion

        #region Plugin body
        public static string PluginBody_AuthorWithoutDownloadCount(string author) => $" 作者：{author}";
        public static string PluginBody_AuthorWithDownloadCount(string author, long count) => $" 作者：{author} ({count:N0} 次下载)";
        public static string PluginBody_AuthorWithDownloadCountUnavailable(string author) => $" 作者：{author}";
        public static string PluginBody_CurrentChangeLog(Version version) => $"更新日志 (v{version})";
        public static string PluginBody_UpdateChangeLog(Version version) => $"可用更新日志 (v{version})";
        public static string PluginBody_DevPluginPath(string path) => $"来源：{path}";
        public static string PluginBody_Plugin3rdPartyRepo(string url) => $"来源：{url}";
        public static string PluginBody_Outdated => "此插件已过时且不兼容。";
        public static string PluginBody_Incompatible => "此插件与当前 Dalamud 版本不兼容。请尝试重启游戏。";
        public static string PluginBody_Outdated_WaitForUpdate => "请等待作者更新。";
        public static string PluginBody_Outdated_CanNowUpdate => "有可用更新可安装。";
        public static string PluginBody_Orphaned => "此插件的源仓库不再可用。可能需要从其仓库重新安装，或重新添加仓库。";
        public static string PluginBody_NoServiceOfficial => "此插件不再维护。它仍然可以工作，但不会有进一步的更新，且无法重新安装。";
        public static string PluginBody_NoServiceThird => "此插件不再由其源仓库维护。可能需要在其他仓库中寻找更新版本。";
        public static string PluginBody_NoServiceThirdCrossUpdate => "此插件不再由其源仓库维护。有可用更新，将更新到官方仓库的版本。";
        public static string PluginBody_LoadFailed => "此插件加载失败。请联系作者获取更多信息。";
        public static string PluginBody_Banned => "此插件因不兼容而被自动禁用，目前不可用。";
        public static string PluginBody_Policy => "此类型的插件加载已被手动禁用。";
        public static string PluginBody_BannedReason(string message) => $"此插件已被自动禁用：{message}";
        #endregion

        #region Plugin buttons
        public static string PluginButton_InstallVersion(string version) => $"安装 v{version}";
        public static string PluginButton_Working => "处理中";
        public static string PluginButton_Disable => "禁用";
        public static string PluginButton_Load => "加载";
        public static string PluginButton_Unload => "卸载";
        public static string PluginButton_SafeMode => "安全模式下无法更改";
        public static string PluginButton_OpenUi => "打开";
        public static string PluginButton_OpenSettings => "设置";
        #endregion

        #region Plugin button tooltips

        public static string PluginButtonToolTip_OpenUi => Loc.Localize("InstallerTooltipOpenUi", "Open this plugin's interface");

        public static string PluginButtonToolTip_OpenConfiguration => Loc.Localize("InstallerTooltipOpenConfig", "Open this plugin's settings");

        public static string PluginButtonToolTip_PickProfiles => Loc.Localize("InstallerPickProfiles", "Pick collections for this plugin");

        public static string PluginButtonToolTip_ProfilesNotSupported => Loc.Localize("InstallerProfilesNotSupported", "This plugin does not support collections");

        public static string PluginButtonToolTip_StartOnBoot => Loc.Localize("InstallerStartOnBoot", "Start on boot");

        public static string PluginButtonToolTip_AutomaticReloading => Loc.Localize("InstallerAutomaticReloading", "Automatic reloading");

        public static string PluginButtonToolTip_NotifyForErrors => Loc.Localize("InstallerNotifyForErrors", "Show Dalamud notifications when this plugin is creating errors");

        public static string PluginButtonToolTip_DeletePlugin => Loc.Localize("InstallerDeletePlugin ", "Delete plugin");

        public static string PluginButtonToolTip_DeletePluginRestricted => Loc.Localize("InstallerDeletePluginRestricted", "Cannot delete right now - please restart the game.");

        public static string PluginButtonToolTip_DeletePluginScheduled => Loc.Localize("InstallerDeletePluginScheduled", "Delete plugin on next restart");

        public static string PluginButtonToolTip_DeletePluginScheduledCancel => Loc.Localize("InstallerDeletePluginScheduledCancel", "Cancel scheduled deletion");

        public static string PluginButtonToolTip_DeletePluginLoaded => Loc.Localize("InstallerDeletePluginLoaded", "Disable this plugin before deleting it.");

        public static string PluginButtonToolTip_VisitPluginUrl => Loc.Localize("InstallerVisitPluginUrl", "Visit plugin URL");

        public static string PluginButtonToolTip_UpdateSingle(string version) => Loc.Localize("InstallerUpdateSingle", "Update to {0}").Format(version);

        public static string PluginButtonToolTip_LoadUnloadFailed => Loc.Localize("InstallerLoadUnloadFailedTooltip", "Plugin load/unload failed, please restart your game and try again.");

        public static string PluginButtonToolTip_NeedsToBeInDefault => Loc.Localize("InstallerUnloadNeedsToBeInDefault", "This plugin is in one or more collections. If you want to enable or disable it, please do so by enabling or disabling the collections it is in.\nIf you want to manage it manually, remove it from all collections.");

        public static string PluginButtonToolTip_NeedsToBeInSingleProfile => Loc.Localize("InstallerUnloadNeedsToBeInSingleProfile", "This plugin is in more than one collection. If you want to enable or disable it, please do so by enabling or disabling the collections it is in.\nIf you want to manage it here, make sure it is only in a single collection.");

        public static string PluginButtonToolTip_SafeMode => Loc.Localize("InstallerButtonSafeModeTooltip", "Cannot enable plugins in safe mode.");

        public static string PluginButtonToolTip_SingleProfileDisabled(string name) => Loc.Localize("InstallerSingleProfileDisabled", "The collection '{0}' which contains this plugin is disabled.\nPlease enable it in the collections manager to toggle the plugin individually.").Format(name);

        public static string PluginButtonToolTip_SingleProfileDoesNotWantActive(string name) => Loc.Localize("InstallerSingleProfileDoesNotWantActive", "The collection '{0}' which contains this plugin is active, but is not set to activate on this character.\nPlease change the collection's settings or remove the plugin from that collection to toggle the plugin individually.").Format(name);

        #endregion

        #region Notifications
        public static string Notifications_PluginInstalledTitle => "插件已安装";
        public static string Notifications_PluginInstalled(string name) => $"'{name}' 已成功安装。";
        public static string Notifications_PluginNotInstalledTitle => "插件未安装";
        public static string Notifications_PluginNotInstalled(string name) => $"'{name}' 安装失败。";
        public static string Notifications_NoUpdatesFoundTitle => "未找到更新";
        public static string Notifications_NoUpdatesFound => "未找到任何更新。";
        public static string Notifications_UpdatesInstalledTitle => "更新已安装";
        public static string Notifications_UpdatesInstalled(List<PluginUpdateStatus> updates)
            => $"{updates.Count} 个插件已更新。\n\n{string.Join(", ", updates.Select(x => x.InternalName))}";
        public static string Notifications_PluginDisabledTitle => "插件已禁用";
        public static string Notifications_PluginDisabled(string name) => $"'{name}' 已被禁用。";
        public static string Notifications_PluginEnabledTitle => "插件已启用";
        public static string Notifications_PluginEnabled(string name) => $"'{name}' 已被启用。";
        #endregion

        #region Footer
        public static string FooterButton_UpdatePlugins => "更新插件";
        public static string FooterButton_UpdateSafeMode => "安全模式下无法更新";
        public static string FooterButton_InProgress => "安装进行中...";
        public static string FooterButton_NoUpdates => "未找到更新";
        public static string FooterButton_UpdateComplete(int count) => $"{count} 个插件已更新";
        public static string FooterButton_Settings => "设置";
        public static string FooterButton_ScanDevPlugins => "扫描开发版插件";
        public static string FooterButton_Close => "关闭";
        #endregion

        #region Update modal
        public static string UpdateModal_Title => "可用更新";
        public static string UpdateModal_UpdateAvailable(string name) => $"插件 \"{name}\" 有可用更新。\n是否在启用前更新？\n更新将修复错误和不兼容问题，并可能添加新功能。";
        public static string UpdateModal_Yes => "更新插件";
        public static string UpdateModal_No => "仅启用";
        #endregion

        #region Error modal
        public static string ErrorModal_Title => "安装器错误";
        public static string ErrorModal_InstallContactAuthor => "请重启游戏并重试。如果此错误再次出现，请联系插件作者。";
        public static string ErrorModal_InstallFail(string name) => $"安装插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_SingleUpdateFail(string name, string why) => $"更新插件 {name} 失败 ({why})。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_DeleteConfigFail(string name) => $"重置插件 {name} 失败。\n\n该插件可能不支持此操作。可尝试在游戏关闭时手动删除配置 - 请参阅常见问题解答。";
        public static string ErrorModal_EnableFail(string name) => $"启用插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_DisableFail(string name) => $"禁用插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_UnloadFail(string name) => $"卸载插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_LoadFail(string name) => $"加载插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_DeleteFail(string name) => $"删除插件 {name} 失败。\n{ErrorModal_InstallContactAuthor}";
        public static string ErrorModal_UpdaterFatal => "更新插件失败。\n请重启游戏并重试。如果此错误再次出现，请向开发团队反馈。";
        public static string ErrorModal_ProfileApplyFail => "处理合集失败。\n请重启游戏并重试。如果此错误再次出现，请向开发团队反馈。";
        public static string ErrorModal_UpdaterFail(int failCount) => $"更新 {failCount} 个插件失败。\n请重启游戏并重试。如果此错误再次出现，请向开发团队反馈。";
        public static string ErrorModal_UpdaterFailPartial(int successCount, int failCount) => $"已更新 {successCount} 个插件，{failCount} 个更新失败。\n请重启游戏并重试。如果此错误再次出现，请向开发团队反馈。";
        public static string ErrorModal_HintBlame(string plugins) => $"\n\n以下插件导致了这些问题：\n\n{plugins}\n可尝试手动删除这些插件并重新安装。";
        #endregion

        #region Feedback Modal
        public static string FeedbackModal_Title => "发送反馈";
        public static string FeedbackModal_Text(string pluginName) => $"可在此处向插件 \"{pluginName}\" 的开发者发送反馈。";
        public static string FeedbackModal_HasUpdate => "此插件有新版本可用，请在报告问题前先更新。";
        public static string FeedbackModal_ContactAnonymous => "匿名提交反馈";
        public static string FeedbackModal_ContactAnonymousWarning => $"将不会收到任何回复。\n如需帮助，请取消勾选 \"{FeedbackModal_ContactAnonymous}\" 并提供联系信息。";
        public static string FeedbackModal_ContactInformation => "联系信息";
        public static string FeedbackModal_ContactInformationHelp => "接受 Discord 用户名和电子邮件地址。\n如提交 Discord 用户名，请加入 Discord 服务器，以便更容易联系。";
        public static string FeedbackModal_ContactInformationWarning => "请勿提交游戏内角色名称。";
        public static string FeedbackModal_ContactInformationRequired => "未提供联系信息。需要联系信息来回复问题，或请求额外信息以解决问题。";
        public static string FeedbackModal_ContactInformationDiscordButton => "加入 XIVLauncher & Dalamud Discord";
        public static string FeedbackModal_ContactInformationDiscordUrl => "https://goat.place/";
        public static string FeedbackModal_IncludeLastError => "包含最后的错误信息";
        public static string FeedbackModal_IncludeLastErrorHint => "此选项可以为插件开发者提供关于具体问题的有用反馈。";
        public static string FeedbackModal_Hint => "所有插件开发者都将能够看到反馈内容。\n请勿包含任何个人或敏感信息。\n如选择包含最后的错误信息，可能会包含诸如 Windows 用户名等信息。\n\n收集的反馈不会存储在服务端，而是直接转发到 Discord。";
        public static string FeedbackModal_NotificationSuccess => "反馈已成功发送";
        public static string FeedbackModal_NotificationError => "无法发送反馈";
        #endregion

        #region Testing Warning Modal
        public static string TestingWarningModal_Title => "警告###InstallerTestingWarning";
        public static string TestingWarningModal_DowngradeBody => "注意！退出插件测试版后，将继续使用测试版，直到删除并重新安装插件，或者插件的非测试版本更新。\n手动降级可能会丢失此插件的设置。";
        #endregion

        #region Delete Plugin Config Warning Modal
        public static string DeletePluginConfigWarningModal_Title => "警告###InstallerDeletePluginConfigWarning";
        public static string DeletePluginConfigWarningModal_ExplainTesting() => "如仅想禁用测试版，请勿选择此选项！";
        public static string DeletePluginConfigWarningModal_Body(string pluginName) => $"确定要删除 {pluginName} 的所有数据和配置吗？\n将丢失此插件的所有设置。";
        public static string DeletePluginConfirmWarningModal_Yes => "是";
        public static string DeletePluginConfirmWarningModal_No => "否";
        #endregion

        #region Plugin Update chatbox
        public static string PluginUpdateHeader_Chatbox => "更新：";
        #endregion

        #region Error modal buttons
        public static string ErrorModalButton_Ok => "确定";
        #endregion

        #region Other
        public static string SafeModeDisclaimer => "安全模式已启用，不会加载任何插件。\n可从\"已安装插件\"标签页删除插件。\n重启游戏即可禁用安全模式。";
        #endregion

        #region Profiles
        public static string Profiles_CouldNotAdd => "无法将插件添加到此合集";
        public static string Profiles_CouldNotRemove => "无法从此合集中移除插件";
        public static string Profiles_None => "没有合集, 请在\"插件合集\"中添加";
        public static string Profiles_RemoveFromAll => "从所有合集中移除";
        #endregion
    }
}
