using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using Dalamud.Configuration.Internal;
using Dalamud.Plugin.Internal;
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
    private readonly PluginCategoryManager categoryManager = new();

    [SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1201:Elements should appear in the correct order", Justification = "Makes sense like this")]
    private List<RemotePluginManifest> pluginListAvailable = [];

    private List<LocalPlugin> pluginListInstalled = [];

    private List<AvailablePluginUpdate> pluginListUpdatable = [];

    private int availablePluginsChanged;

    private int installedPluginsChanged;

    private PluginSearchQuery? searchQuery;

    private readonly Dictionary<(string Source, string Name), RemotePluginManifest> availableManifestsBySource = [];

    private readonly Dictionary<LocalPlugin, AvailablePluginUpdate> updatesByPlugin = [];

    private bool hasAvailablePluginList;

    private bool hasDevPlugins;

    private bool hasHiddenPlugins;

    private string searchText = string.Empty;

    private bool isSearchTextPrefilled;

    private PluginSortKind sortKind = PluginSortKind.Alphabetical;

    private string filterText = "按字母顺序";

    private bool adaptiveSort = true;

    private bool showInstalledPlugins = true;

    private bool showThirdPartyPlugins = true;

    private bool showUnsupportedPlugins = true;

    private enum PluginSortKind
    {
        Alphabetical,
        DownloadCount,
        LastUpdate,
        NewOrNot,
        EnabledDisabled,
        ProfileOrNot,
        SearchScore
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
        Favorite
    }

    /// <summary>
    /// Sets the current search text and marks it as prefilled.
    /// </summary>
    /// <param name="text">The search term.</param>
    public void SetSearchText
    (
        string text
    )
    {
        if (string.IsNullOrEmpty(text))
        {
            this.isSearchTextPrefilled = false;
            this.ClearSearch();
        }
        else
        {
            this.isSearchTextPrefilled = true;
            this.searchText            = text;
            this.sortKind              = PluginSortKind.SearchScore;
            this.filterText            = "搜索权重";
            this.ResortPlugins();
        }
    }

    private static bool ShouldRenderAsTestingExclusive
    (
        RemotePluginManifest? manifest
    )
    {
        if (manifest == null)
            return false;

        return manifest.IsTestingExclusive ||
               (manifest.TestingDalamudApiLevel == PluginManager.DalamudApiLevel &&
                manifest.TestingDalamudApiLevel != manifest.DalamudApiLevel);
    }

    /// <summary>
    /// Clear the search text and reset all associated state (sort mode, category highlights, open collapsibles).
    /// </summary>
    private void ClearSearch()
    {
        this.searchText = string.Empty;

        if (this.adaptiveSort || this.sortKind == PluginSortKind.SearchScore)
        {
            this.sortKind   = PluginSortKind.Alphabetical;
            this.filterText = "按字母顺序";
        }

        this.ResortPlugins();

        this.UpdateCategoriesOnSearchChange();
    }

    private bool IsInstalledDevPluginsCategory()
        => this.categoryManager.CurrentGroupKind    == PluginCategoryManager.GroupKind.DevTools &&
           this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.DevInstalled;

    private bool HasActivePluginFilters()
    {
        if (this.IsInstalledDevPluginsCategory())
            return false;

        var installedFilterActive = this.categoryManager.CurrentGroupKind != PluginCategoryManager.GroupKind.Installed && !this.showInstalledPlugins;
        return installedFilterActive || !this.showThirdPartyPlugins || !this.showUnsupportedPlugins;
    }

    private bool IsAvailablePluginProxyFiltered
    (
        PluginInstallerAvailablePluginProxy proxy
    )
    {
        if (proxy.LocalPlugin != null && this.IsInstalledPluginFiltered(proxy.LocalPlugin, true))
            return true;

        if (proxy.LocalPlugin == null && proxy.RemoteManifest != null)
        {
            if (!this.showThirdPartyPlugins && proxy.RemoteManifest.SourceRepo.IsThirdParty)
                return true;

            if (!this.showUnsupportedPlugins && IsAvailableManifestUnsupported(proxy.RemoteManifest))
                return true;
        }

        return false;
    }

    private bool IsInstalledPluginFiltered
    (
        LocalPlugin plugin,
        bool        applyInstalledFilter
    )
    {
        if (applyInstalledFilter && !this.showInstalledPlugins)
            return true;

        if (!this.showThirdPartyPlugins && plugin.IsThirdParty)
            return true;

        return !this.showUnsupportedPlugins && IsInstalledPluginUnsupported(plugin);
    }

    private static bool IsAvailableManifestUnsupported
    (
        RemotePluginManifest manifest
    )
    {
        var pluginManager = Service<PluginManager>.Get();
        return IsAvailableManifestOutdated(manifest, pluginManager.UseTesting(manifest)) || IsAvailableManifestIncompatible(manifest);
    }

    private static bool IsAvailableManifestOutdated
    (
        RemotePluginManifest manifest,
        bool                 useTesting
    )
    {
        var effectiveApiLevel = useTesting && manifest.TestingDalamudApiLevel.HasValue ?
                                    manifest.TestingDalamudApiLevel.Value :
                                    manifest.DalamudApiLevel;

        return effectiveApiLevel < PluginManager.DalamudApiLevel;
    }

    private static bool IsAvailableManifestIncompatible
    (
        RemotePluginManifest manifest
    )
        => manifest.MinimumDalamudVersion != null && manifest.MinimumDalamudVersion > Versioning.GetAssemblyVersionParsed();

    private static bool IsInstalledPluginUnsupported
    (
        LocalPlugin plugin
    )
        => plugin.IsOutdated || plugin.IsBanned || plugin.IsOrphaned || plugin.IsDecommissioned;

    private bool IsManifestFiltered
    (
        IPluginManifest manifest
    )
    {
        if (string.IsNullOrWhiteSpace(this.searchText))
            return false;

        return this.GetManifestSearchScore(manifest) < 100;
    }

    private int GetManifestSearchScore
    (
        IPluginManifest manifest
    )
    {
        if (this.searchQuery == null || this.searchQuery.Text != this.searchText)
            this.searchQuery = new PluginSearchQuery(this.searchText);

        return this.searchQuery.GetScore(manifest);
    }

    private void OnAvailablePluginsChanged() => Interlocked.Exchange(ref this.availablePluginsChanged, 1);

    private void ApplyAvailablePluginsChanges()
    {
        var pluginManager = Service<PluginManager>.Get();
        var configuration = Service<DalamudConfiguration>.Get();

        var availablePlugins = pluginManager.AvailablePlugins.ToList();
        var preserveOrder    = this.IsOpen && this.hasAvailablePluginList;

        if (preserveOrder)
        {
            var previousOrder = new Dictionary<(string RepoUrl, string InternalName), int>();

            for (var i = 0; i < this.pluginListAvailable.Count; i++)
            {
                var manifest = this.pluginListAvailable[i];
                previousOrder.TryAdd((manifest.SourceRepo.PluginMasterUrl, manifest.InternalName), i);
            }

            availablePlugins =
            [
                .. availablePlugins.OrderBy
                (manifest =>
                     previousOrder.GetValueOrDefault((manifest.SourceRepo.PluginMasterUrl, manifest.InternalName), int.MaxValue)
                )
            ];
        }

        this.pluginItemHeights.Clear();
        this.pluginListAvailable    = availablePlugins;
        this.pluginListUpdatable    = [.. pluginManager.UpdatablePlugins];
        this.hasAvailablePluginList = true;
        this.RebuildCatalogIndexes();
        if (!preserveOrder)
            this.ResortPlugins();

        this.hasHiddenPlugins = this.pluginListAvailable.Any(x => configuration.HiddenPluginInternalName.Contains(x.InternalName));

        var wasContentDirty = this.categoryManager.IsContentDirty;
        this.UpdateCategoriesOnPluginsChange();
        if (!wasContentDirty && preserveOrder)
            this.categoryManager.ResetContentDirty();

        if (this.updateStatus != OperationStatus.InProgress)
        {
            this.updateStatus      = OperationStatus.Idle;
            this.updatePluginCount = 0;
            this.updatedPlugins    = null;
        }
    }

    private void OnInstalledPluginsChanged() => Interlocked.Exchange(ref this.installedPluginsChanged, 1);

    private void ApplyInstalledPluginsChanges()
    {
        var pluginManager = Service<PluginManager>.Get();

        using (pluginManager.GetSyncScope())
        {
            this.pluginListInstalled = [.. pluginManager.InstalledPlugins];
            this.pluginListUpdatable = [.. pluginManager.UpdatablePlugins];
        }

        this.hasDevPlugins = this.pluginListInstalled.Any(plugin => plugin.IsDev);
        this.RebuildCatalogIndexes();
        this.ResortPlugins();
        this.UpdateCategoriesOnPluginsChange();
    }

    private void RebuildCatalogIndexes()
    {
        this.searchQuery = null;
        this.availableManifestsBySource.Clear();
        this.updatesByPlugin.Clear();

        foreach (var manifest in this.pluginListAvailable)
            this.availableManifestsBySource.TryAdd((manifest.SourceRepo.PluginMasterUrl, manifest.InternalName), manifest);

        foreach (var update in this.pluginListUpdatable)
            this.updatesByPlugin.TryAdd(update.InstalledPlugin, update);
    }

    private RemotePluginManifest? FindAvailableManifest
    (
        LocalPlugin plugin
    )
    {
        if (plugin.IsDev)
            return null;

        var source = plugin.Manifest.InstalledFromUrl;
        if (source == SpecialPluginSource.MainRepo)
            source = Service<DalamudConfiguration>.Get().MainRepoUrl;

        return this.availableManifestsBySource.GetValueOrDefault((source, plugin.InternalName));
    }

    private void ResortPlugins()
    {
        this.pluginItemHeights.Clear();

        switch (this.sortKind)
        {
            case PluginSortKind.Alphabetical:
                this.pluginListAvailable.Sort((p1, p2) => StringComparer.CurrentCulture.Compare(p1.Name,          p2.Name));
                this.pluginListInstalled.Sort((p1, p2) => StringComparer.CurrentCulture.Compare(p1.Manifest.Name, p2.Manifest.Name));
                break;
            case PluginSortKind.DownloadCount:
                this.pluginListAvailable.Sort((p1, p2) => p2.DownloadCount.CompareTo(p1.DownloadCount));
                this.pluginListInstalled.Sort((p1, p2) => p2.Manifest.DownloadCount.CompareTo(p1.Manifest.DownloadCount));
                break;
            case PluginSortKind.LastUpdate:
                this.pluginListAvailable.Sort((p1, p2) => p2.LastUpdate.CompareTo(p1.LastUpdate));
                this.pluginListInstalled.Sort
                ((p1, p2) =>
                    {
                        // We need to get remote manifests here, as the local manifests will have the time when the current version is installed,
                        // not the actual time of the last update, as the plugin may be pending an update
                        IPluginManifest? p2Considered = this.FindAvailableManifest(p2);
                        p2Considered ??= p2.Manifest;

                        IPluginManifest? p1Considered = this.FindAvailableManifest(p1);
                        p1Considered ??= p1.Manifest;

                        return p2Considered.LastUpdate.CompareTo(p1Considered.LastUpdate);
                    }
                );
                break;
            case PluginSortKind.NewOrNot:
                this.pluginListAvailable.Sort
                ((p1, p2) => WasPluginSeen(p1.InternalName)
                     .CompareTo(WasPluginSeen(p2.InternalName))
                );
                this.pluginListInstalled.Sort
                ((p1, p2) => WasPluginSeen(p1.Manifest.InternalName)
                     .CompareTo(WasPluginSeen(p2.Manifest.InternalName))
                );
                break;
            case PluginSortKind.EnabledDisabled:
                var installedNames = this.pluginListInstalled.Select(plugin => plugin.InternalName).ToHashSet(StringComparer.Ordinal);
                this.pluginListAvailable.Sort((p1, p2) => installedNames.Contains(p2.InternalName).CompareTo(installedNames.Contains(p1.InternalName)));
                this.pluginListInstalled.Sort((p1, p2) => (p2.State == PluginState.Loaded).CompareTo(p1.State == PluginState.Loaded));
                break;
            case PluginSortKind.ProfileOrNot:
                this.pluginListAvailable.Sort((p1, p2) => StringComparer.CurrentCulture.Compare(p1.Name, p2.Name));

                var profman = Service<ProfileManager>.Get();
                this.pluginListInstalled.Sort
                    ((p1, p2) => profman.IsInDefaultProfile(p1.EffectiveWorkingPluginId).CompareTo(profman.IsInDefaultProfile(p2.EffectiveWorkingPluginId)));
                break;
            case PluginSortKind.SearchScore:
                this.pluginListAvailable = [.. this.pluginListAvailable.OrderByDescending(this.GetManifestSearchScore).ThenBy(m => m.Name)];
                this.pluginListInstalled = [.. this.pluginListInstalled.OrderByDescending(p => this.GetManifestSearchScore(p.Manifest)).ThenBy(m => m.Name)];
                break;
            default:
                throw new InvalidEnumArgumentException("Unknown plugin sort type.");
        }

        this.SortPluginsByPinnedStatus();
    }

    private void SortPluginsByPinnedStatus()
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pinnedList    = new HashSet<string>(configuration.PinnedPluginInternalName);

        this.pluginListAvailable = [.. this.pluginListAvailable.OrderByDescending(plugin => pinnedList.Contains(plugin.InternalName))];

        this.pluginListInstalled =
        [
            .. this.pluginListInstalled
                   .OrderByDescending(p => pinnedList.Contains(p.Manifest.InternalName))
        ];
    }

    private static bool WasPluginSeen
    (
        string internalName
    ) =>
        Service<DalamudConfiguration>.Get().SeenPluginInternalName.Contains(internalName);

    private void UpdateCategoriesOnSearchChange()
    {
        if (string.IsNullOrEmpty(this.searchText))
        {
            this.categoryManager.SetCategoryHighlightsForPlugins([]);
        }
        else
        {
            var pluginsMatchingSearch = this.pluginListAvailable.Where(rm => !this.IsManifestFiltered(rm)).ToArray();

            this.categoryManager.SetCategoryHighlightsForPlugins(pluginsMatchingSearch);
        }
    }

    private void UpdateCategoriesOnPluginsChange()
    {
        this.categoryManager.BuildCategories(this.pluginListAvailable);
        this.UpdateCategoriesOnSearchChange();
    }
}
