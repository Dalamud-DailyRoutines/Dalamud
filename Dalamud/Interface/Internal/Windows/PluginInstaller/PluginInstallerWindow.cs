using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Threading;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Windowing;
using Dalamud.Logging.Internal;
using Dalamud.Plugin.Internal;
using Dalamud.Support;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow : Window, IDisposable
{
    private static readonly ModuleLog Log = ModuleLog.Create<PluginInstallerWindow>();

    private readonly PluginImageCache imageCache;

    private readonly DateTime timeLoaded;

    private readonly Lock listLock = new();

    private bool disposed;

    private readonly ProfileManagerWidget profileManagerWidget;

    private string? staleDalamudNewVersion;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstallerWindow"/> class.
    /// </summary>
    /// <param name="imageCache">An instance of <see cref="PluginImageCache"/> class.</param>
    /// <param name="configuration">An instance of <see cref="DalamudConfiguration"/>.</param>
    [SuppressMessage("ReSharper", "UnusedParameter.Local", Justification = "Preserves the existing constructor signature.")]
    public PluginInstallerWindow
    (
        PluginImageCache     imageCache,
        DalamudConfiguration configuration
    )
        : base("插件安装器###XlPluginInstaller", ImGuiWindowFlags.NoScrollbar)
    {
        this.pluginListInstalled = [];
        this.IsOpen              = true;
        this.imageCache          = imageCache;

        this.Size          = new Vector2(830, 570);
        this.SizeCondition = ImGuiCond.FirstUseEver;

        this.SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = this.Size.Value
        };

        Service<PluginManager>.GetAsync().ContinueWith
        (pluginManagerTask =>
            {
                if (!pluginManagerTask.IsCompletedSuccessfully)
                {
                    Log.Error(pluginManagerTask.Exception, "插件管理器初始化失败");
                    return;
                }

                using var scope = this.listLock.EnterScope();
                if (this.disposed)
                    return;

                var pluginManager = pluginManagerTask.Result;

                // For debugging
                if (pluginManager.PluginsReady)
                    this.OnInstalledPluginsChanged();

                this.dalamudChangelogManager = new(pluginManager);

                pluginManager.OnAvailablePluginsChanged += this.OnAvailablePluginsChanged;
                pluginManager.OnInstalledPluginsChanged += this.OnInstalledPluginsChanged;

                this.OnAvailablePluginsChanged();

                for (var i = 0; i < this.testerImagePaths.Length; i++)
                {
                    this.testerImagePaths[i] = string.Empty;
                }
            }
        );

        this.timeLoaded = DateTime.Now;

        this.profileManagerWidget = new(this);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        using var scope = this.listLock.EnterScope();
        if (this.disposed)
            return;

        this.disposed = true;
        this.dalamudChangelogRefreshTaskCts?.Cancel();
        this.dalamudChangelogRefreshTaskCts?.Dispose();
        this.errorModalTaskCompletionSource?.TrySetResult();
        this.updateModalTaskCompletionSource?.TrySetCanceled();
        this.deletePluginConfigWarningModalTaskCompletionSource?.TrySetResult(false);
        _ = this.testerIcon?.ToContentDisposedTask();

        if (this.testerImages != null)
        {
            foreach (var image in this.testerImages)
                _ = image?.ToContentDisposedTask();
        }

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
    public void OpenTo
    (
        PluginInstallerOpenKind kind
    )
    {
        this.IsOpen = true;
        this.SetOpenPage(kind);
    }

    /// <summary>
    /// Toggle to the installer to the page specified by <paramref name="kind"/>.
    /// </summary>
    /// <param name="kind">The page of the installer to open.</param>
    public void ToggleTo
    (
        PluginInstallerOpenKind kind
    )
    {
        this.Toggle();

        if (this.IsOpen)
            this.SetOpenPage(kind);
    }

    /// <inheritdoc/>
    public override void OnOpen()
    {
        var pluginManager = Service<PluginManager>.Get();

        _ = pluginManager.ReloadAllReposAsync(false);
        _ = pluginManager.ScanDevPluginsAsync();

        if (!this.isSearchTextPrefilled)
        {
            this.ClearSearch();
        }

        if (this.updateStatus is OperationStatus.Complete or OperationStatus.Idle)
        {
            this.updateStatus      = OperationStatus.Idle;
            this.updatePluginCount = 0;
            this.updatedPlugins    = null;
        }

        this.profileManagerWidget.Reset();

        if (this.staleDalamudNewVersion == null && !Versioning.GetActiveTrack().IsNullOrEmpty())
        {
            Service<DalamudReleases>.Get().GetVersionForCurrentTrack().ContinueWith
            (t =>
                {
                    if (!t.IsCompletedSuccessfully)
                        return;

                    var versionInfo = t.Result;

                    if (versionInfo.AssemblyVersion != Versioning.GetScmVersion())
                    {
                        this.staleDalamudNewVersion = versionInfo.AssemblyVersion;
                    }
                }
            );
        }
    }

    /// <inheritdoc/>
    public override void OnClose()
    {
        Service<DalamudConfiguration>.Get().QueueSave();

        if (this.isSearchTextPrefilled)
        {
            this.isSearchTextPrefilled = false;
            this.ClearSearch();
        }
    }

    /// <inheritdoc/>
    public override void Draw()
    {
        using var scope = this.listLock.EnterScope();
        if (this.disposed)
            return;

        var pluginManager = Service<PluginManager>.Get();
        if ((pluginManager.ReposReady || (!this.hasAvailablePluginList && pluginManager.HasLoadedRepos)) &&
            Interlocked.Exchange(ref this.availablePluginsChanged, 0) != 0)
            this.ApplyAvailablePluginsChanges();

        if (Interlocked.Exchange(ref this.installedPluginsChanged, 0) != 0)
            this.ApplyInstalledPluginsChanges();

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

    /// <summary>
    /// Clear the icon and image caches, forcing a fresh download.
    /// </summary>
    public void ClearIconCache() => this.imageCache.ClearIconCache();
}
