using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private static readonly (string Label, PluginSortKind Kind)[] SortOptions =
    [
        ("名称", PluginSortKind.Alphabetical),
        ("下载次数", PluginSortKind.DownloadCount),
        ("最近更新", PluginSortKind.LastUpdate),
        ("新插件优先", PluginSortKind.NewOrNot),
        ("启用状态", PluginSortKind.EnabledDisabled),
        ("在合集中", PluginSortKind.ProfileOrNot)
    ];

    private void SetOpenPage
    (
        PluginInstallerOpenKind kind
    )
    {
        switch (kind)
        {
            case PluginInstallerOpenKind.AllPlugins:
                // Plugins group
                this.categoryManager.CurrentGroupKind    = PluginCategoryManager.GroupKind.Available;
                // All category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.InstalledPlugins:
                // Installed group
                this.categoryManager.CurrentGroupKind    = PluginCategoryManager.GroupKind.Installed;
                // All category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.UpdateablePlugins:
                // Installed group
                this.categoryManager.CurrentGroupKind    = PluginCategoryManager.GroupKind.Installed;
                // Updateable category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.UpdateablePlugins;
                break;
            case PluginInstallerOpenKind.Changelogs:
                // Changelog group
                this.categoryManager.CurrentGroupKind    = PluginCategoryManager.GroupKind.Changelog;
                // Plugins category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.All;
                break;
            case PluginInstallerOpenKind.DalamudChangelogs:
                // Changelog group
                this.categoryManager.CurrentGroupKind    = PluginCategoryManager.GroupKind.Changelog;
                // Dalamud category
                this.categoryManager.CurrentCategoryKind = PluginCategoryManager.CategoryKind.DalamudChangelogs;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, null);
        }
    }

    private void DrawHeader()
    {
        var style = ImGui.GetStyle();
        var isProfileManager =
            this.categoryManager.CurrentGroupKind    == PluginCategoryManager.GroupKind.Installed &&
            this.categoryManager.CurrentCategoryKind == PluginCategoryManager.CategoryKind.PluginProfiles;
        var isChangelog         = this.categoryManager.CurrentGroupKind == PluginCategoryManager.GroupKind.Changelog;
        var disableListControls = isChangelog || isProfileManager;
        var availableWidth      = ImGui.GetContentRegionAvail().X;
        var rowStartX           = ImGui.GetCursorPosX();
        var buttonSize          = new Vector2(ImGui.GetFrameHeight());
        var sortWidth = SortOptions.Max
                            (option => ImGui.CalcTextSize(option.Label).X) +
                        (style.FramePadding.X * 2)                         +
                        ImGui.GetFrameHeight()                             +
                        (24 * ImGuiHelpers.GlobalScale);
        var searchWidth      = Math.Min(240 * ImGuiHelpers.GlobalScale, Math.Max(1, availableWidth - sortWidth - (buttonSize.X * 2) - (style.ItemSpacing.X * 3)));
        var searchGroupWidth = searchWidth + (buttonSize.X * 2) + (style.ItemSpacing.X * 2);

        using (ImRaii.Disabled(disableListControls))
        {
            this.DrawPluginSortSelector(sortWidth);
        }

        ImGui.SameLine(rowStartX + availableWidth - searchGroupWidth);

        using (ImRaii.Disabled(disableListControls))
        {
            const string FILTER_POPUP_ID = "###XlPluginInstaller_FilterPopup";
            var          filterActive    = this.HasActivePluginFilters();
            if (ImGuiComponents.IconButton
                (
                    "###XlPluginInstaller_FilterToggle",
                    FontAwesomeIcon.Filter,
                    filterActive ?
                        ImGuiColors.SuccessBackground with { W = 0.35f } :
                        null,
                    null,
                    null,
                    buttonSize / ImGuiHelpers.GlobalScale
                ))
                ImGui.OpenPopup(FILTER_POPUP_ID);

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("筛选");

            var popupPosition = ImGui.GetItemRectMin() + new Vector2(0, ImGui.GetItemRectSize().Y + style.ItemSpacing.Y);
            ImGui.SetNextWindowPos(popupPosition, ImGuiCond.Appearing);

            using (var filterPopup = ImRaii.Popup(FILTER_POPUP_ID, ImGuiWindowFlags.AlwaysAutoResize))
            {
                if (filterPopup)
                    this.DrawPluginFilterPopup();
            }
        }

        ImGui.SameLine();

        using (ImRaii.Disabled(isProfileManager))
        {
            ImGui.SetNextItemWidth(searchWidth);
            var searchChanged = ImGui.InputTextWithHint
            (
                "###XlPluginInstaller_Search"u8,
                isChangelog ?
                    "搜索日志" :
                    "搜索插件",
                ref this.searchText,
                256,
                ImGuiInputTextFlags.AutoSelectAll
            );
            var clearSearch = ImGui.IsItemActive() && ImGui.IsKeyPressed(ImGuiKey.Escape);
            ImGui.SameLine();

            using (ImRaii.Disabled(this.searchText.Length == 0))
            {
                clearSearch |= ImGuiComponents.IconButton("###XlPluginInstaller_ClearSearch", FontAwesomeIcon.Times, buttonSize / ImGuiHelpers.GlobalScale);
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("清空搜索");

            if (clearSearch)
                this.ClearSearch();
            else if (searchChanged)
                this.ApplySearchChange();
        }

        ImGui.Separator();
    }

    private void DrawPluginSortSelector(float width)
    {
        var sortLabel = SortOptions.First(option => option.Kind == this.sortKind).Label;
        ImGui.SetNextItemWidth(width);
        using var combo = ImRaii.Combo("###XlPluginInstaller_Sort", sortLabel);
        if (!combo)
            return;

        var changed = false;

        foreach (var option in SortOptions)
        {
            var selected = this.sortKind == option.Kind;

            if (ImGui.Selectable(option.Label, selected))
            {
                this.sortKind = option.Kind;
                changed       = true;
            }
        }

        if (!changed)
            return;

        this.ResortPlugins();
        this.openPluginCollapsibles.Clear();
        this.pluginItemHeights.Clear();
    }

    private void DrawPluginFilterPopup()
    {
        var configuration = Service<DalamudConfiguration>.Get();

        var filtersChanged                = false;
        var isInstalledDevPluginsCategory = this.IsInstalledDevPluginsCategory();
        var installedFilterDisabled       = this.categoryManager.CurrentGroupKind == PluginCategoryManager.GroupKind.Installed || isInstalledDevPluginsCategory;


        var includeInstalled   = installedFilterDisabled       || this.showInstalledPlugins;
        var includeThirdParty  = isInstalledDevPluginsCategory || this.showThirdPartyPlugins;
        var includeUnsupported = isInstalledDevPluginsCategory || this.showUnsupportedPlugins;

        using (ImRaii.Disabled(installedFilterDisabled))
        {
            if (ImGui.Checkbox("包含已安装插件###XlPluginInstaller_FilterInstalled", ref includeInstalled) && !installedFilterDisabled)
            {
                this.showInstalledPlugins = includeInstalled;
                filtersChanged            = true;
            }
        }

        if (configuration.ThirdRepoList.Any(repo => repo.IsEnabled))
        {
            using (ImRaii.Disabled(isInstalledDevPluginsCategory))
            {
                if (ImGui.Checkbox("包含第三方插件###XlPluginInstaller_FilterThirdParty", ref includeThirdParty) && !isInstalledDevPluginsCategory)
                {
                    this.showThirdPartyPlugins = includeThirdParty;
                    filtersChanged             = true;
                }
            }
        }

        using (ImRaii.Disabled(isInstalledDevPluginsCategory))
        {
            if (ImGui.Checkbox("包含未兼容插件###XlPluginInstaller_FilterUnsupported", ref includeUnsupported) && !isInstalledDevPluginsCategory)
            {
                this.showUnsupportedPlugins = includeUnsupported;
                filtersChanged              = true;
            }
        }

        ImGui.Separator();

        using (ImRaii.Disabled(!this.HasActivePluginFilters()))
        {
            if (ImGui.Button("重置筛选"))
            {
                this.showInstalledPlugins   = true;
                this.showThirdPartyPlugins  = true;
                this.showUnsupportedPlugins = false;
                filtersChanged              = true;
            }
        }

        if (!filtersChanged)
            return;

        this.openPluginCollapsibles.Clear();
        this.pluginItemHeights.Clear();
    }

    private void DrawFooter()
    {
        var configuration = Service<DalamudConfiguration>.Get();
        var pluginManager = Service<PluginManager>.Get();

        var windowSize            = ImGui.GetWindowContentRegionMax();
        var placeholderButtonSize = ImGuiHelpers.GetButtonSize("placeholder");

        ImGui.Separator();

        ImGui.SetCursorPosY(windowSize.Y - placeholderButtonSize.Y);

        this.DrawUpdatePluginsButton();

        ImGui.SameLine();
        if (ImGui.Button("扫描开发版插件"))
            _ = pluginManager.ScanDevPluginsAsync();

        ImGui.SameLine();

        using (ImRaii.Disabled(!pluginManager.ReposReady || this.AnyOperationInProgress))
        {
            if (ImGui.Button
                (
                    pluginManager.ReposReady ?
                        "刷新插件列表" :
                        "正在刷新插件列表……"
                ))
                _ = pluginManager.ReloadAllReposAsync();
        }

        ImGui.SameLine();
        if (ImGui.Button("设置"))
            Service<DalamudInterface>.Get().OpenSettings();

        const string CLOSE_TEXT      = "关闭";
        var          closeButtonSize = ImGuiHelpers.GetButtonSize(CLOSE_TEXT);

        ImGui.SameLine(windowSize.X - closeButtonSize.X - 20);

        if (ImGui.Button(CLOSE_TEXT))
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
            ImGuiComponents.DisabledButton("安全模式下无法更新");
        }
        else if (!ready || this.availablePluginsChanged != 0 || this.updateStatus == OperationStatus.InProgress || this.installStatus == OperationStatus.InProgress)
        {
            ImGuiComponents.DisabledButton
            (
                ready ?
                    "更新插件" :
                    "等待刷新后更新"
            );
        }
        else if (this.updateStatus == OperationStatus.Complete)
        {
            ImGui.Button
            (
                this.updatePluginCount > 0 ?
                    $"{this.updatePluginCount} 个插件已更新" :
                    "未找到更新"
            );
        }
        else
        {
            if (ImGui.Button("更新插件"))
            {
                this.updateStatus         = OperationStatus.InProgress;
                this.loadingIndicatorKind = LoadingIndicatorKind.UpdatingAll;

                var shouldUpdateDisabledPlugins = Service<DalamudConfiguration>.Get().UpdateDisabledPluginsOnManualUpdate;
                var toUpdate = this.pluginListUpdatable
                                   .Where(x => shouldUpdateDisabledPlugins || x.InstalledPlugin.IsWantedByAnyProfile)
                                   .ToList();

                Task.Run(() => pluginManager.UpdatePluginsAsync(toUpdate, false))
                    .ContinueWith
                    (task =>
                        {
                            this.updateStatus = OperationStatus.Complete;

                            if (!task.IsCompletedSuccessfully)
                            {
                                this.updatePluginCount = 0;
                                this.updatedPlugins    = null;
                                this.DisplayErrorContinuation(task, "更新插件失败\n请重启游戏并重试，如果此错误再次出现，请向开发团队反馈");
                            }
                            else
                            {
                                this.updatedPlugins    = [.. task.Result.Where(res => res.Status == PluginUpdateStatus.StatusKind.Success)];
                                this.updatePluginCount = this.updatedPlugins.Count;

                                var errorPlugins     = task.Result.Where(res => res.Status != PluginUpdateStatus.StatusKind.Success).ToList();
                                var errorPluginCount = errorPlugins.Count;

                                if (errorPluginCount > 0)
                                {
                                    var errorMessage = this.updatePluginCount > 0 ?
                                                           $"已更新 {this.updatePluginCount} 个插件，{errorPluginCount} 个更新失败\n请重启游戏并重试，如果此错误再次出现，请向开发团队反馈" :
                                                           $"更新 {errorPluginCount} 个插件失败\n请重启游戏并重试，如果此错误再次出现，请向开发团队反馈";

                                    var hintInsert = errorPlugins
                                                     .Aggregate
                                                     (
                                                         string.Empty,
                                                         (
                                                                 current, pluginUpdateStatus
                                                             ) =>
                                                             $"{current}* {pluginUpdateStatus.AffectedPlugin.InternalName}（{GetUpdateStatusText(pluginUpdateStatus.Status)}）\n"
                                                     )
                                                     .TrimEnd();
                                    errorMessage += $"\n\n以下插件导致了这些问题：\n\n{hintInsert}\n可尝试手动删除这些插件并重新安装";

                                    this.ShowErrorModal(errorMessage);
                                }

                                if (this.updatePluginCount > 0)
                                {
                                    Service<PluginManager>.Get().PrintUpdatedPlugins(this.updatedPlugins, "更新了插件。");
                                    notifications.AddNotification
                                    (
                                        new Notification
                                        {
                                            Title = "更新已安装",
                                            Content =
                                                $"更新了 {this.updatedPlugins.Count} 个插件。\n\n{string.Join("，", this.updatedPlugins.Select(x => x.AffectedPlugin.InternalName))}",
                                            Type = NotificationType.Success,
                                            Icon = INotificationIcon.From(FontAwesomeIcon.Download)
                                        }
                                    );

                                    this.categoryManager.CurrentGroupKind = PluginCategoryManager.GroupKind.Installed;
                                }
                                else
                                {
                                    notifications.AddNotification("未找到任何更新", "未找到更新", NotificationType.Info);
                                }
                            }
                        }
                    );
            }
        }
    }

    private void DrawPluginCategories()
    {
        const float USE_CONTENT_HEIGHT = -40f; // button height + spacing
        const float USE_MENU_WIDTH     = 180f; // works fine as static value, table can be resized by user

        var useContentWidth = ImGui.GetContentRegionAvail().X;

        using var installerMainChild = ImRaii.Child("InstallerCategories"u8, new Vector2(useContentWidth, USE_CONTENT_HEIGHT * ImGuiHelpers.GlobalScale));

        if (installerMainChild)
        {
            using var style = ImRaii.PushStyle(ImGuiStyleVar.CellPadding, ImGuiHelpers.ScaledVector2(5, 0));

            try
            {
                using (var categoriesChild = ImRaii.Child("InstallerCategoriesSelector"u8, new Vector2(USE_MENU_WIDTH * ImGuiHelpers.GlobalScale, -1), false))
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
            var canShowGroup = groupInfo.GroupKind != PluginCategoryManager.GroupKind.DevTools || this.hasDevPlugins;

            if (!canShowGroup)
            {
                continue;
            }

            var isCurrent = groupInfo.GroupKind == this.categoryManager.CurrentGroupKind;
            ImGui.SetNextItemOpen(isCurrent);

            if (ImGui.CollapsingHeader
                (
                    groupInfo.Name,
                    isCurrent ?
                        ImGuiTreeNodeFlags.OpenOnDoubleClick :
                        ImGuiTreeNodeFlags.None
                ))
            {
                if (!isCurrent)
                {
                    this.categoryManager.CurrentGroupKind = groupInfo.GroupKind;
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

        var pm = Service<PluginManager>.Get();

        if (pm.SafeMode)
        {
            DrawWarningIcon();
            DrawLinesCentered("安全模式已启用，不会加载任何插件\n可从“已安装插件”标签页删除插件\n重启游戏即可禁用安全模式");

            ImGuiHelpers.ScaledDummy(10);
        }

        if (this.staleDalamudNewVersion != null)
        {
            DrawWarningIcon();
            DrawLinesCentered
            (
                "Dalamud 有新版本可用。\n"     +
                "请重启游戏，以确保与更新后的插件兼容。\n" +
                $"当前版本：{Versioning.GetScmVersion()}；新版本：{this.staleDalamudNewVersion}"
            );

            ImGuiHelpers.ScaledDummy(10);
        }

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, ImGuiHelpers.ScaledVector2(1, 3));

        var groupInfo = this.categoryManager.CurrentGroup;

        if (this.categoryManager.IsContentDirty)
        {
            // reset opened list of collapsibles when switching between categories
            this.openPluginCollapsibles.Clear();
            this.pluginItemHeights.Clear();

            // do NOT reset dirty flag when Available group is selected, it will be handled by DrawAvailablePluginList()
            if (groupInfo.GroupKind != PluginCategoryManager.GroupKind.Available)
            {
                this.categoryManager.ResetContentDirty();
            }
        }

        var layout = (ImGui.GetContentRegionAvail().X, ImGui.GetFontSize(), ImGuiHelpers.GlobalScale,
                         ImGui.GetStyle().ItemSpacing, this.categoryManager.CurrentCategoryKind, this.updatedPlugins);

        if (this.pluginListLayout != layout)
        {
            this.pluginItemHeights.Clear();
            this.pluginListLayout = layout;
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
                        ImGui.Text("发现了神秘分类，请替它保密。"u8);
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

                    case PluginCategoryManager.CategoryKind.FavoritePlugins:
                        this.DrawInstalledPluginList(InstalledPluginListFilter.Favorite);
                        break;

                    case PluginCategoryManager.CategoryKind.PluginProfiles:
                        this.profileManagerWidget.Draw();
                        break;

                    default:
                        ImGui.Text("发现了隐藏分类，值得纪念。"u8);
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
                        ImGui.Text("此分类暂时没有内容。"u8);
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

        return;

        void DrawLinesCentered
        (
            string text
        )
        {
            var lines = text.Split('\n');

            foreach (var line in lines)
            {
                ImGuiHelpers.CenteredText(line);
            }
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

    }
}
