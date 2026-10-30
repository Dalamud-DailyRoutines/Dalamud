using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Colors;
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
    private readonly HashSet<string> openPluginCollapsibles = [];

    private readonly HashSet<string> collapsedRepoGroups = [];

    private readonly Dictionary<string, float> pluginItemHeights = [];

    private (float Width, float FontSize, float Scale, Vector2 ItemSpacing, PluginCategoryManager.CategoryKind Category, List<PluginUpdateStatus>? Updates)
        pluginListLayout;

    private record PluginInstallerAvailablePluginProxy
    (
        RemotePluginManifest? RemoteManifest,
        LocalPlugin?          LocalPlugin
    );

    private List<PluginInstallerAvailablePluginProxy> GatherProxies()
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var hiddenNames   = configuration.HiddenPluginInternalName.ToHashSet(StringComparer.Ordinal);
        var showHidden    = this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.Hidden;
        var installedBySource = this.pluginListInstalled.Where(plugin => !plugin.IsDev)
                                    .ToLookup(plugin => (plugin.Manifest.InstalledFromUrl, plugin.InternalName));
        var consumed  = new HashSet<LocalPlugin>();
        var proxies   = new List<PluginInstallerAvailablePluginProxy>();
        var available = this.pluginListAvailable.Where(manifest => !this.IsManifestFiltered(manifest));

        foreach (var manifest in this.categoryManager.GetCurrentCategoryContent(available).Cast<RemotePluginManifest>())
        {
            var source = manifest.SourceRepo.IsThirdParty ?
                             manifest.SourceRepo.PluginMasterUrl :
                             SpecialPluginSource.MainRepo;
            var plugin = installedBySource[(source, manifest.InternalName)].FirstOrDefault();
            if (plugin != null)
                consumed.Add(plugin);

            var proxy = new PluginInstallerAvailablePluginProxy(manifest, plugin);
            if (hiddenNames.Contains(manifest.InternalName) == showHidden &&
                !this.IsAvailablePluginProxyFiltered(proxy))
                proxies.Add(proxy);
        }

        var unmatched = this.pluginListInstalled.Where
        (plugin => !consumed.Contains(plugin) &&
                   !this.IsManifestFiltered(plugin.Manifest)
        );

        var unmatchedByManifest = unmatched.ToDictionary(plugin => (PluginManifest)plugin.Manifest);

        foreach (var manifest in this.categoryManager.GetCurrentCategoryContent(unmatchedByManifest.Keys))
        {
            var plugin = unmatchedByManifest[manifest];
            var proxy  = new PluginInstallerAvailablePluginProxy(null, plugin);
            if (hiddenNames.Contains(plugin.InternalName) == showHidden &&
                !this.IsAvailablePluginProxyFiltered(proxy))
                proxies.Add(proxy);
        }

        return proxies;
    }

    private static void DrawMutedBodyText
    (
        string text,
        float  paddingBefore,
        float  paddingAfter
    )

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
        var proxies = this.GatherProxies();

        if (proxies.Count == 0)
        {
            DrawMutedBodyText("未找到符合条件的插件", 60, 20);
            return;
        }

        var proxyGroups = proxies
                          .GroupBy
                          (p =>
                              {
                                  if (p.LocalPlugin is { IsDev: false })
                                      return p.LocalPlugin.Manifest.InstalledFromUrl == SpecialPluginSource.MainRepo ?
                                                 "主库" :
                                                 p.LocalPlugin.Manifest.InstalledFromUrl;
                                  if (p.RemoteManifest != null)
                                      return p.RemoteManifest.SourceRepo.IsThirdParty ?
                                                 p.RemoteManifest.SourceRepo.PluginMasterUrl :
                                                 "主库";
                                  return "开发版插件";
                              }
                          )
                          .ToList();

        proxyGroups = SortRepositoryGroups(proxyGroups);

        var i = 0;

        foreach (var group in proxyGroups)
        {
            var repoUrl  = group.Key;
            var hasItems = false;

            var sideBar = this.BeginRepoSideBar(repoUrl);

            if (!sideBar.IsCollapsed)
            {
                foreach (var proxy in group)
                {
                    hasItems = true;

                    IPluginManifest applicableManifest = proxy.LocalPlugin != null ?
                                                             proxy.LocalPlugin.Manifest :
                                                             proxy.RemoteManifest;

                    if (applicableManifest == null)
                        throw new Exception("Could not determine manifest for available plugin");

                    ImGui.PushID
                    (
                        proxy.LocalPlugin != null ?
                            $"installed:{proxy.LocalPlugin.EffectiveWorkingPluginId}" :
                            $"{proxy.RemoteManifest!.SourceRepo.PluginMasterUrl}:{applicableManifest.InternalName}"
                    );

                    if (proxy.LocalPlugin != null)
                    {
                        var update = this.updatesByPlugin.GetValueOrDefault(proxy.LocalPlugin);
                        this.DrawInstalledPlugin(proxy.LocalPlugin, i++, proxy.RemoteManifest, update, true);
                    }
                    else if (proxy.RemoteManifest != null)
                    {
                        this.DrawAvailablePlugin(proxy.RemoteManifest, i++);
                    }

                    ImGui.PopID();
                }

                if (!hasItems)
                {
                    ImGui.TextColored
                    (
                        ImGuiColors.DalamudGrey2,
                        string.IsNullOrWhiteSpace(this.searchText) ?
                            "此仓库未找到可用插件" :
                            $"未找到与“{this.searchText}”匹配的插件"
                    );
                }
            }

            this.EndRepoSideBar(in sideBar);
        }

        if (i > 0 &&
            !string.IsNullOrWhiteSpace(this.searchText))
            DrawMutedBodyText($"没有更多与“{this.searchText}”相关的搜索结果", 20, 20);
    }

    private void DrawAvailablePluginList()
    {
        var i = 0;

        foreach (var proxy in this.GatherProxies())
        {
            IPluginManifest applicableManifest = proxy.LocalPlugin != null ?
                                                     proxy.LocalPlugin.Manifest :
                                                     proxy.RemoteManifest;

            if (applicableManifest == null)
                throw new Exception("Could not determine manifest for available plugin");

            ImGui.PushID
            (
                proxy.LocalPlugin != null ?
                    $"installed:{proxy.LocalPlugin.EffectiveWorkingPluginId}" :
                    $"{proxy.RemoteManifest!.SourceRepo.PluginMasterUrl}:{applicableManifest.InternalName}"
            );

            if (proxy.LocalPlugin != null)
            {
                var update = this.updatesByPlugin.GetValueOrDefault(proxy.LocalPlugin);
                this.DrawInstalledPlugin(proxy.LocalPlugin, i++, proxy.RemoteManifest, update, true);
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
            var hasSearch      = !this.searchText.IsNullOrEmpty();
            var hasListFilters = this.HasActivePluginFilters();

            var message = (i == 0, hasSearch, hasListFilters) switch
            {
                (true, false, false) => "当前没有可用的插件",
                (true, _, _)         => "未找到符合搜索条件的插件",
                (false, true, _)     => $"没有更多与“{this.searchText}”相关的搜索结果",
                _                    => null
            };
            if (message != null)
                DrawMutedBodyText
                (
                    message,
                    i == 0 ?
                        60 :
                        20,
                    20
                );
        }
    }

    private void DrawInstalledPluginList
    (
        InstalledPluginListFilter filter
    )
    {
        if (Service<DalamudConfiguration>.Get().UseSoilPluginManager)
        {
            this.DrawInstalledPluginListSoil(filter);
            return;
        }

        var entries = this.GatherInstalledPlugins(filter);
        var i       = 0;
        foreach (var entry in entries)
            this.DrawInstalledPlugin(entry.Plugin, i++, entry.Remote, entry.Update, false);

        var drewAny = entries.Count > 0;

        if (!drewAny)
        {
            var text = filter switch
            {
                InstalledPluginListFilter.None         => "尚未安装任何插件\n可从“所有插件”标签页安装",
                InstalledPluginListFilter.Testing      => "当前没有正在测试的插件\n可在插件右键菜单中选择接收测试版",
                InstalledPluginListFilter.Updateable   => "当前没有可更新的插件",
                InstalledPluginListFilter.Dev          => "没有开发版插件，可在设置中添加",
                InstalledPluginListFilter.Enabled      => "没有已启用的插件",
                InstalledPluginListFilter.Disabled     => "没有已禁用的插件",
                InstalledPluginListFilter.Incompatible => "没有不兼容的插件",
                InstalledPluginListFilter.Favorite     => "无已收藏插件。\n可在右键菜单内收藏。",
                _                                      => throw new ArgumentException(null, nameof(filter))
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
            DrawMutedBodyText($"没有更多与“{this.searchText}”相关的搜索结果", 20, 20);
            ImGuiHelpers.ScaledDummy(20);
        }
    }

    private void DrawInstalledPluginListSoil
    (
        InstalledPluginListFilter filter
    )
    {
        var validPlugins = this.GatherInstalledPlugins(filter);

        if (validPlugins.Count == 0)
        {
            var text = filter switch
            {
                InstalledPluginListFilter.None         => "尚未安装任何插件\n可从“所有插件”标签页安装",
                InstalledPluginListFilter.Testing      => "当前没有正在测试的插件\n可在插件右键菜单中选择接收测试版",
                InstalledPluginListFilter.Updateable   => "当前没有可更新的插件",
                InstalledPluginListFilter.Dev          => "没有开发版插件，可在设置中添加",
                InstalledPluginListFilter.Enabled      => "没有已启用的插件",
                InstalledPluginListFilter.Disabled     => "没有已禁用的插件",
                InstalledPluginListFilter.Incompatible => "没有不兼容的插件",
                InstalledPluginListFilter.Favorite     => "尚未收藏任何插件。\n可通过右键菜单收藏。",
                _                                      => throw new ArgumentException(null, nameof(filter))
            };

            ImGuiHelpers.ScaledDummy(60);

            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
            {
                foreach (var line in text.Split('\n'))
                {
                    ImGuiHelpers.CenteredText(line);
                }
            }

            return;
        }

        var groups = validPlugins.GroupBy(x => x.RepoUrl).ToList();

        groups = SortRepositoryGroups(groups);

        var i = 0;

        foreach (var group in groups)
        {
            var sideBar = this.BeginRepoSideBar(group.Key);

            if (!sideBar.IsCollapsed)
            {
                foreach (var (plugin, remote, update, _) in group)
                {
                    this.DrawInstalledPlugin(plugin, i++, remote, update, false);
                }
            }

            this.EndRepoSideBar(in sideBar);
        }

        if (!this.searchText.IsNullOrEmpty())
        {
            DrawMutedBodyText($"没有更多与“{this.searchText}”相关的搜索结果", 20, 20);
            ImGuiHelpers.ScaledDummy(20);
        }
    }

    private List<(LocalPlugin Plugin, RemotePluginManifest? Remote, AvailablePluginUpdate? Update, string RepoUrl)> GatherInstalledPlugins
    (
        InstalledPluginListFilter filter
    )
    {
        var manager       = Service<PluginManager>.Get();
        var configuration = Service<DalamudConfiguration>.Get();
        var favorites     = configuration.FavoritePluginInternalName.ToHashSet(StringComparer.Ordinal);
        var entries       = new List<(LocalPlugin Plugin, RemotePluginManifest? Remote, AvailablePluginUpdate? Update, string RepoUrl)>();

        foreach (var plugin in this.pluginListInstalled)
        {
            if (this.IsManifestFiltered(plugin.Manifest))
                continue;

            if (filter != InstalledPluginListFilter.Dev &&
                this.IsInstalledPluginFiltered(plugin, false))
                continue;

            var update = this.updatesByPlugin.GetValueOrDefault(plugin);
            var matches = filter switch
            {
                InstalledPluginListFilter.None         => true,
                InstalledPluginListFilter.Testing      => manager.HasTestingOptIn(plugin.Manifest),
                InstalledPluginListFilter.Updateable   => update != null,
                InstalledPluginListFilter.Dev          => plugin.IsDev,
                InstalledPluginListFilter.Enabled      => plugin.IsWantedByAnyProfile  && !IsInstalledPluginUnsupported(plugin),
                InstalledPluginListFilter.Disabled     => !plugin.IsWantedByAnyProfile && !IsInstalledPluginUnsupported(plugin),
                InstalledPluginListFilter.Incompatible => IsInstalledPluginUnsupported(plugin),
                InstalledPluginListFilter.Favorite     => favorites.Contains(plugin.InternalName),
                _                                      => throw new ArgumentOutOfRangeException(nameof(filter), filter, null)
            };
            if (!matches)
                continue;

            var remote = this.FindAvailableManifest(plugin);
            var source = plugin.Manifest.InstalledFromUrl;
            if (plugin.IsDev)
                source = "开发版插件";
            else if (source == SpecialPluginSource.MainRepo || source == configuration.MainRepoUrl)
                source = "主库";

            entries.Add((plugin, remote, update, source));
        }

        return entries;
    }

    private bool ClipPluginItem
    (
        string pluginKey
    )
    {
        if (!this.pluginItemHeights.TryGetValue(pluginKey, out var height) ||
            ImGui.IsRectVisible(new Vector2(this.pluginListLayout.Width, height)))
            return false;

        ImGui.Dummy(new Vector2(0, MathF.Max(0, height - this.pluginListLayout.ItemSpacing.Y)));
        return true;
    }
}
