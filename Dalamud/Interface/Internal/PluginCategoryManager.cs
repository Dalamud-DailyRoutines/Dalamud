using System.Collections.Generic;
using System.Linq;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Plugin.Internal.Types.Manifest;

namespace Dalamud.Interface.Internal;

/// <summary>
/// Manage category filters for PluginInstallerWindow.
/// </summary>
internal class PluginCategoryManager
{
    /// <summary>
    /// First categoryId for tag based categories.
    /// </summary>
    private const int FIRST_TAG_BASED_CATEGORY_ID = 100;

    private int          currentGroupIdx     = 2;
    private CategoryKind currentCategoryKind = CategoryKind.All;

    private Dictionary<PluginManifest, CategoryKind[]> mapPluginCategories      = [];
    private List<CategoryKind>                         highlightedCategoryKinds = [];

    /// <summary>
    /// Type of category group.
    /// </summary>
    public enum GroupKind
    {
        /// <summary>
        /// UI group: dev mode only.
        /// </summary>
        DevTools,

        /// <summary>
        /// UI group: installed plugins.
        /// </summary>
        Installed,

        /// <summary>
        /// UI group: plugins that can be installed.
        /// </summary>
        Available,

        /// <summary>
        /// UI group: changelog of plugins.
        /// </summary>
        Changelog
    }

    /// <summary>
    /// Type of category.
    /// </summary>
    public enum CategoryKind
    {
        /// <summary>
        /// All plugins.
        /// </summary>
        All = 0,

        /// <summary>
        /// Plugins currently being tested.
        /// </summary>
        IsTesting = 1,

        /// <summary>
        /// Plugins available for testing.
        /// </summary>
        AvailableForTesting = 2,

        /// <summary>
        /// Plugins that were hidden.
        /// </summary>
        Hidden = 3,

        /// <summary>
        /// Installed dev plugins.
        /// </summary>
        DevInstalled = 10,

        /// <summary>
        /// Icon tester.
        /// </summary>
        IconTester = 11,

        /// <summary>
        /// Changelogs for Dalamud.
        /// </summary>
        DalamudChangelogs = 12,

        /// <summary>
        /// Changelogs for plugins.
        /// </summary>
        PluginChangelogs = 13,

        /// <summary>
        /// Change plugin profiles.
        /// </summary>
        PluginProfiles = 14,

        /// <summary>
        /// Updateable plugins.
        /// </summary>
        UpdateablePlugins = 15,

        /// <summary>
        /// Enabled plugins.
        /// </summary>
        EnabledPlugins = 16,

        /// <summary>
        /// Disabled plugins.
        /// </summary>
        DisabledPlugins = 17,

        /// <summary>
        /// Incompatible plugins.
        /// </summary>
        IncompatiblePlugins = 18,

        /// <summary>
        /// Favorite plugins.
        /// </summary>
        FavoritePlugins = 19,

        /// <summary>
        /// Plugins tagged as "other".
        /// </summary>
        Other = FIRST_TAG_BASED_CATEGORY_ID + 0,

        /// <summary>
        /// Plugins tagged as "jobs".
        /// </summary>
        Jobs = FIRST_TAG_BASED_CATEGORY_ID + 1,

        /// <summary>
        /// Plugins tagged as "ui".
        /// </summary>
        Ui = FIRST_TAG_BASED_CATEGORY_ID + 2,

        /// <summary>
        /// Plugins tagged as "minigames".
        /// </summary>
        MiniGames = FIRST_TAG_BASED_CATEGORY_ID + 3,

        /// <summary>
        /// Plugins tagged as "inventory".
        /// </summary>
        Inventory = FIRST_TAG_BASED_CATEGORY_ID + 4,

        /// <summary>
        /// Plugins tagged as "sound".
        /// </summary>
        Sound = FIRST_TAG_BASED_CATEGORY_ID + 5,

        /// <summary>
        /// Plugins tagged as "social".
        /// </summary>
        Social = FIRST_TAG_BASED_CATEGORY_ID + 6,

        /// <summary>
        /// Plugins tagged as "utility".
        /// </summary>
        Utility = FIRST_TAG_BASED_CATEGORY_ID + 7
    }

    /// <summary>
    /// Gets the list of all known categories.
    /// </summary>
    public CategoryInfo[] CategoryList { get; } =
    [
        new(CategoryKind.All, "special.all", "所有"),
        new(CategoryKind.IsTesting, "special.isTesting", "测试版", CategoryInfo.AppearCondition.DoPluginTest),
        new(CategoryKind.AvailableForTesting, "special.availableForTesting", "可测试", CategoryInfo.AppearCondition.DoPluginTest),
        new(CategoryKind.Hidden, "special.hidden", "已隐藏", CategoryInfo.AppearCondition.AnyHiddenPlugins),
        new(CategoryKind.DevInstalled, "special.devInstalled", "已安装开发版插件"),
        new(CategoryKind.IconTester, "special.devIconTester", "图像与图标测试"),
        new(CategoryKind.DalamudChangelogs, "special.dalamud", "Dalamud"),
        new(CategoryKind.PluginChangelogs, "special.plugins", "插件"),
        new(CategoryKind.PluginProfiles, "special.profiles", "插件合集"),
        new(CategoryKind.UpdateablePlugins, "special.updateable", "可更新"),
        new(CategoryKind.EnabledPlugins, "special.enabled", "已启用"),
        new(CategoryKind.DisabledPlugins, "special.disabled", "已禁用"),
        new(CategoryKind.IncompatiblePlugins, "special.incompatible", "不兼容"),
        new(CategoryKind.FavoritePlugins, "special.favorite", "收藏"),

        // Tag-driven categories
        new(CategoryKind.Other, "other", "其他"),
        new(CategoryKind.Jobs, "jobs", "职业"),
        new(CategoryKind.Ui, "ui", "界面"),
        new(CategoryKind.MiniGames, "minigames", "小游戏"),
        new(CategoryKind.Inventory, "inventory", "背包"),
        new(CategoryKind.Sound, "sound", "音效"),
        new(CategoryKind.Social, "social", "社交"),
        new(CategoryKind.Utility, "utility", "实用工具")

        // order doesn't matter, all tag driven categories should have Id >= FIRST_TAG_BASED_CATEGORY_ID
    ];

    /// <summary>
    /// Gets the list of all known UI groups.
    /// </summary>
    public GroupInfo[] GroupList { get; } =
    [
        new(GroupKind.DevTools, "开发工具", CategoryKind.DevInstalled, CategoryKind.IconTester),
        new
        (
            GroupKind.Installed,
            "已安装插件",
            CategoryKind.All,
            CategoryKind.IsTesting,
            CategoryKind.UpdateablePlugins,
            CategoryKind.EnabledPlugins,
            CategoryKind.DisabledPlugins,
            CategoryKind.IncompatiblePlugins,
            CategoryKind.FavoritePlugins,
            CategoryKind.PluginProfiles
        ),
        new(GroupKind.Available, "所有插件", CategoryKind.All),
        new(GroupKind.Changelog, "更新日志", CategoryKind.All, CategoryKind.DalamudChangelogs, CategoryKind.PluginChangelogs)

        // order important, used for drawing, keep in sync with defaults for currentGroupIdx
    ];

    /// <summary>
    /// Gets or sets the current group kind.
    /// </summary>
    public GroupKind CurrentGroupKind
    {
        get => this.GroupList[this.currentGroupIdx].GroupKind;
        set
        {
            var newIdx = Array.FindIndex(this.GroupList, x => x.GroupKind == value);

            if (newIdx >= 0)
            {
                this.currentGroupIdx     = newIdx;
                this.currentCategoryKind = this.CurrentGroup.Categories.First();
                this.IsContentDirty      = true;
            }
        }
    }

    /// <summary>
    /// Gets information about currently selected group.
    /// </summary>
    public GroupInfo CurrentGroup => this.GroupList[this.currentGroupIdx];

    /// <summary>
    /// Gets or sets the current category kind.
    /// </summary>
    public CategoryKind CurrentCategoryKind
    {
        get => this.currentCategoryKind;
        set
        {
            if (this.currentCategoryKind != value)
            {
                this.currentCategoryKind = value;
                this.IsContentDirty      = true;
            }
        }
    }

    /// <summary>
    /// Gets information about currently selected category.
    /// </summary>
    public CategoryInfo CurrentCategory => this.CategoryList.First(x => x.CategoryKind == this.currentCategoryKind);

    /// <summary>
    /// Gets a value indicating whether current group + category selection changed recently.
    /// Changes in Available group should be followed with <see cref="GetCurrentCategoryContent"/>, everything else can use <see cref="ResetContentDirty"/>.
    /// </summary>
    public bool IsContentDirty { get; private set; }

    /// <summary>
    /// Gets a value indicating whether <see cref="CurrentCategoryKind"/> and <see cref="CurrentGroupKind"/> are valid.
    /// </summary>
    public bool IsSelectionValid =>
        this.currentGroupIdx >= 0                    &&
        this.currentGroupIdx < this.GroupList.Length &&
        this.GroupList[this.currentGroupIdx].Categories.Contains(this.currentCategoryKind);

    /// <summary>
    /// Rebuild available categories based on currently available plugins.
    /// </summary>
    /// <param name="availablePlugins">list of all available plugin manifests to install.</param>
    public void BuildCategories
    (
        IEnumerable<RemotePluginManifest> availablePlugins
    )
    {
        // rebuild map plugin name -> categoryIds
        this.mapPluginCategories.Clear();

        var groupAvail      = Array.Find(this.GroupList, x => x.GroupKind == GroupKind.Available);
        var prevCategoryIds = new List<CategoryKind>();
        prevCategoryIds.AddRange(groupAvail.Categories);

        var categoryList       = new List<CategoryKind>();
        var allCategoryIndices = new List<int>();

        foreach (var manifest in availablePlugins)
        {
            categoryList.Clear();

            var pluginCategoryTags = manifest.CategoryTags;

            if (pluginCategoryTags != null)
            {
                foreach (var tag in pluginCategoryTags)
                {
                    // only tags from whitelist can be accepted
                    var matchIdx = Array.FindIndex(this.CategoryList, x => x.Tag.Equals(tag, StringComparison.InvariantCultureIgnoreCase));

                    if (matchIdx >= 0)
                    {
                        var categoryKind = this.CategoryList[matchIdx].CategoryKind;

                        if ((int)categoryKind >= FIRST_TAG_BASED_CATEGORY_ID)
                        {
                            categoryList.Add(categoryKind);

                            if (!allCategoryIndices.Contains(matchIdx))
                            {
                                allCategoryIndices.Add(matchIdx);
                            }
                        }
                    }
                }
            }

            if (manifest.IsTestingExclusive || manifest.IsAvailableForTesting)
                categoryList.Add(CategoryKind.AvailableForTesting);

            // always add, even if empty
            this.mapPluginCategories.Add(manifest, [.. categoryList]);
        }

        // 按显示名称排序分类。
        allCategoryIndices.Sort((idxX, idxY) => StringComparer.Ordinal.Compare(this.CategoryList[idxX].Name, this.CategoryList[idxY].Name));
        allCategoryIndices.Insert(0, 2); // "Available for testing"

        // rebuild all categories in group, leaving first entry = All intact and always on top
        if (groupAvail.Categories.Count > 1)
        {
            groupAvail.Categories.RemoveRange(1, groupAvail.Categories.Count - 1);
        }

        foreach (var categoryIdx in allCategoryIndices)
        {
            groupAvail.Categories.Add(this.CategoryList[categoryIdx].CategoryKind);
        }

        // Hidden at the end
        groupAvail.Categories.Add(CategoryKind.Hidden);

        // compare with prev state and mark as dirty if needed
        var noCategoryChanges = prevCategoryIds.SequenceEqual(groupAvail.Categories);

        if (!noCategoryChanges)
        {
            this.IsContentDirty = true;
        }
    }

    /// <summary>
    /// Filters list of available plugins based on currently selected category.
    /// Resets <see cref="IsContentDirty"/>.
    /// </summary>
    /// <param name="plugins">List of available plugins to install.</param>
    /// <returns>Filtered list of plugins.</returns>
    public List<PluginManifest> GetCurrentCategoryContent
    (
        IEnumerable<PluginManifest> plugins
    )
    {
        var result = new List<PluginManifest>();

        if (this.IsSelectionValid)
        {
            var groupInfo = this.GroupList[this.currentGroupIdx];

            var includeAll = this.currentCategoryKind == CategoryKind.All    ||
                             this.currentCategoryKind == CategoryKind.Hidden ||
                             groupInfo.GroupKind      != GroupKind.Available;

            if (includeAll)
            {
                result.AddRange(plugins);
            }
            else
            {
                var selectedCategoryInfo = Array.Find(this.CategoryList, x => x.CategoryKind == this.currentCategoryKind);

                foreach (var plugin in plugins)
                {
                    if (this.mapPluginCategories.TryGetValue(plugin, out var pluginCategoryIds))
                    {
                        var matchIdx = Array.IndexOf(pluginCategoryIds, selectedCategoryInfo.CategoryKind);

                        if (matchIdx >= 0)
                        {
                            result.Add(plugin);
                        }
                    }
                    else if ((int)selectedCategoryInfo.CategoryKind                                                    >= FIRST_TAG_BASED_CATEGORY_ID &&
                             plugin.CategoryTags?.Contains(selectedCategoryInfo.Tag, StringComparer.OrdinalIgnoreCase) == true)
                    {
                        result.Add(plugin);
                    }
                }
            }
        }

        this.ResetContentDirty();
        return result;
    }

    /// <summary>
    /// Clears <see cref="IsContentDirty"/> flag, indicating that all cached values about currently selected group + category have been updated.
    /// </summary>
    public void ResetContentDirty() => this.IsContentDirty = false;

    /// <summary>
    /// Sets category highlight based on list of plugins. Used for searching.
    /// </summary>
    /// <param name="plugins">List of plugins whose categories should be highlighted.</param>
    public void SetCategoryHighlightsForPlugins
    (
        IEnumerable<PluginManifest> plugins
    )
    {
        ArgumentNullException.ThrowIfNull(plugins);

        this.highlightedCategoryKinds.Clear();

        foreach (var entry in plugins)
        {
            if (this.mapPluginCategories.TryGetValue(entry, out var pluginCategories))
            {
                foreach (var categoryKind in pluginCategories)
                {
                    if (!this.highlightedCategoryKinds.Contains(categoryKind))
                    {
                        this.highlightedCategoryKinds.Add(categoryKind);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Checks if category should be highlighted.
    /// </summary>
    /// <param name="categoryKind">CategoryKind to check.</param>
    /// <returns>true if highlight is needed.</returns>
    public bool IsCategoryHighlighted
    (
        CategoryKind categoryKind
    ) => this.highlightedCategoryKinds.Contains(categoryKind);

    /// <summary>
    /// Plugin installer category info.
    /// </summary>
    public struct CategoryInfo
    {
        /// <summary>
        /// Unique Id number of category, tag match based should be greater of equal <see cref="FIRST_TAG_BASED_CATEGORY_ID"/>.
        /// </summary>
        public CategoryKind CategoryKind;

        /// <summary>
        /// Tag from plugin manifest to match.
        /// </summary>
        public string Tag;

        /// <summary>
        /// Initializes a new instance of the <see cref="CategoryInfo"/> struct.
        /// </summary>
        /// <param name="categoryKind">Kind of the category.</param>
        /// <param name="tag">Tag to match.</param>
        /// <param name="name">显示名称。</param>
        /// <param name="condition">Condition to be checked when deciding whether this category should be shown.</param>
        public CategoryInfo
        (
            CategoryKind    categoryKind,
            string          tag,
            string          name,
            AppearCondition condition = AppearCondition.None
        )
        {
            this.CategoryKind = categoryKind;
            this.Tag          = tag;
            this.Name         = name;
            this.Condition    = condition;
        }

        /// <summary>
        /// Conditions for categories.
        /// </summary>
        public enum AppearCondition
        {
            /// <summary>
            /// Check no conditions.
            /// </summary>
            None,

            /// <summary>
            /// Check if plugin testing is enabled.
            /// </summary>
            DoPluginTest,

            /// <summary>
            /// Check if there are any hidden plugins.
            /// </summary>
            AnyHiddenPlugins
        }

        /// <summary>
        /// Gets or sets the condition to be checked when rendering.
        /// </summary>
        public AppearCondition Condition { get; set; }

        /// <summary>
        /// Gets the name of category.
        /// </summary>
        public string Name { get; }
    }

    /// <summary>
    /// Plugin installer UI group, a container for categories.
    /// </summary>
    public struct GroupInfo
    {
        /// <summary>
        /// Type of group.
        /// </summary>
        public GroupKind GroupKind;

        /// <summary>
        /// List of categories in container.
        /// </summary>
        public List<CategoryKind> Categories;

        /// <summary>
        /// Initializes a new instance of the <see cref="GroupInfo"/> struct.
        /// </summary>
        /// <param name="groupKind">Type of group.</param>
        /// <param name="name">显示名称。</param>
        /// <param name="categories">List of category Ids to hardcode.</param>
        public GroupInfo
        (
            GroupKind             groupKind,
            string                name,
            params CategoryKind[] categories
        )
        {
            this.GroupKind = groupKind;
            this.Name      = name;

            this.Categories = [.. categories];
        }

        /// <summary>
        /// Gets the name of UI group.
        /// </summary>
        public string Name { get; }
    }
}
