using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiFileDialog;
using Dalamud.Interface.Internal.DesignSystem;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.AutoUpdate;
using Dalamud.Plugin.Internal.Types;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.Settings.Tabs;

// REGION TODO: 国服 Dalamud 修改
[SuppressMessage(
    "StyleCop.CSharp.DocumentationRules",
    "SA1600:Elements should be documented",
    Justification = "Internals")]
internal class SettingsTabPlugin : SettingsTab
{
    public override SettingsEntry[] Entries => [];

    public override string Title => "插件";

    public override SettingsOpenKind Kind => SettingsOpenKind.Plugin;

    private DalamudConfiguration Config => Service<DalamudConfiguration>.Get();

    private List<ThirdPartyRepoSettings> thirdRepoList = [];
    private bool                         thirdRepoListChanged;
    private string                       thirdRepoTempUrl  = string.Empty;
    private string                       thirdRepoAddError = string.Empty;

    private List<DevPluginLocationSettings> devPluginLocations = [];
    private bool                            devPluginLocationsChanged;
    private string                          devPluginTempLocation     = string.Empty;
    private string                          devPluginLocationAddError = string.Empty;
    private FileDialogManager               fileDialogManager         = new();

    private AutoUpdateBehavior         behavior;
    private bool                       updateDisabledPlugins;
    private bool                       checkPeriodically;
    private bool                       chatNotification;
    private string                     pickerSearch          = string.Empty;
    private List<AutoUpdatePreference> autoUpdatePreferences = [];

    public override void OnClose()
    {
        thirdRepoList      = [.. Service<DalamudConfiguration>.Get().ThirdRepoList.Select(x => x.Clone())];
        devPluginLocations = [.. Service<DalamudConfiguration>.Get().DevPluginLoadLocations.Select(x => x.Clone())];
    }

    public override void Load()
    {
        thirdRepoList        = [.. Service<DalamudConfiguration>.Get().ThirdRepoList.Select(x => x.Clone())];
        thirdRepoListChanged = false;

        devPluginLocations        = [.. Service<DalamudConfiguration>.Get().DevPluginLoadLocations.Select(x => x.Clone())];
        devPluginLocationsChanged = false;

        behavior              = Config.AutoUpdateBehavior ?? AutoUpdateBehavior.None;
        updateDisabledPlugins = Config.UpdateDisabledPlugins;
        chatNotification      = Config.SendUpdateNotificationToChat;
        checkPeriodically     = Config.CheckPeriodicallyForUpdates;
        autoUpdatePreferences = Config.PluginAutoUpdatePreferences;
    }

    public override void Save()
    {
        Config.ThirdRepoList = [.. thirdRepoList.Select(x => x.Clone())];

        if (thirdRepoListChanged)
        {
            _                    = Service<PluginManager>.Get().SetPluginReposFromConfigAsync(true);
            thirdRepoListChanged = false;
        }

        Config.DevPluginLoadLocations = [.. devPluginLocations.Select(x => x.Clone())];

        if (devPluginLocationsChanged)
        {
            _                         = Service<PluginManager>.Get().ScanDevPluginsAsync();
            devPluginLocationsChanged = false;
        }

        Config.AutoUpdateBehavior           = behavior;
        Config.UpdateDisabledPlugins        = updateDisabledPlugins;
        Config.SendUpdateNotificationToChat = chatNotification;
        Config.CheckPeriodicallyForUpdates  = checkPeriodically;
        Config.PluginAutoUpdatePreferences  = autoUpdatePreferences;
    }

    public override void PostDraw() => fileDialogManager.Draw();

    public override void Draw()
    {
        using var tab = ImRaii.TabBar("插件##Dalamud.Settings.Tabs.Plugin.Tab");

        using (var generalItem = ImRaii.TabItem("一般##Dalamud.Settings.Tabs.Plugin.Tab.General"))
        {
            if (generalItem)
                DrawGeneralTabItem();
        }

        using (var autoUpdateItem = ImRaii.TabItem("自动更新##Dalamud.Settings.Tabs.Plugin.Tab.AutoUpdate"))
        {
            if (autoUpdateItem)
                DrawAutoUpdateTabItem();
        }

        using (var thirdRepoItem = ImRaii.TabItem("第三方插件##Dalamud.Settings.Tabs.Plugin.Tab.ThirdRepo"))
        {
            if (thirdRepoItem)
                DrawThirdRepoTabItem();
        }

        using (var localPluginItem = ImRaii.TabItem("本地插件##Dalamud.Settings.Tabs.Plugin.Tab.LocalPlugin"))
        {
            if (localPluginItem)
                DrawLocalPluginTabItem();
        }
    }

    private static bool ValidThirdPartyRepoUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uriResult)
           && (uriResult.Scheme == Uri.UriSchemeHttps || uriResult.Scheme == Uri.UriSchemeHttp);

    private static bool ValidDevPluginPath(string path)
        => Path.IsPathRooted(path) && Path.GetExtension(path) == ".dll";

    private void AddDevPlugin()
    {
        devPluginTempLocation = devPluginTempLocation.Trim('"');

        if (devPluginLocations.Any(r => string.Equals(r.Path, devPluginTempLocation, StringComparison.InvariantCultureIgnoreCase)))
        {
            devPluginLocationAddError = "[路径已存在]";
            Task.Delay(5000).ContinueWith(_ => devPluginLocationAddError = string.Empty);
        }
        else if (!ValidDevPluginPath(devPluginTempLocation))
        {
            devPluginLocationAddError = "[路径无效]";
            Task.Delay(5000).ContinueWith(_ => devPluginLocationAddError = string.Empty);
        }
        else
        {
            devPluginLocations.Add(
                new DevPluginLocationSettings
                {
                    Path      = devPluginTempLocation,
                    IsEnabled = true
                });
            devPluginLocationsChanged = true;
            devPluginTempLocation     = string.Empty;
        }
    }

    private void DrawGeneralTabItem()
    {
        var mainRepoUrl          = Config.MainRepoUrl;
        var useSoilPluginManager = Config.UseSoilPluginManager;

        ImGui.Text("默认主库");

        if (ImGui.RadioButton("国服 (Daily Routines)", mainRepoUrl == PluginRepository.MainRepoUrlSoil))
        {
            Config.MainRepoUrl = PluginRepository.MainRepoUrlSoil;
            Config.QueueSave();

            _ = Service<PluginManager>.Get().SetPluginReposFromConfigAsync(true);
        }

        ImGui.SameLine();

        if (ImGui.RadioButton("国际服 (goatcorp)", mainRepoUrl == PluginRepository.MainRepoUrlGoatCorp))
        {
            Config.MainRepoUrl = PluginRepository.MainRepoUrlGoatCorp;
            Config.QueueSave();

            _ = Service<PluginManager>.Get().SetPluginReposFromConfigAsync(true);
        }

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Text("自定义主库链接");

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "修改主库链接, 如果不清楚什么是主库，那就不应该修改下面内容");

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.SetNextItemWidth(-1f);
        ImGui.InputText("###CustomMainRepo", ref mainRepoUrl, 1024);

        if (ImGui.IsItemDeactivatedAfterEdit())
        {
            if (string.IsNullOrWhiteSpace(mainRepoUrl))
                mainRepoUrl = PluginRepository.MainRepoUrlSoil;

            Config.MainRepoUrl = mainRepoUrl;
            Config.QueueSave();

            _ = Service<PluginManager>.Get().SetPluginReposFromConfigAsync(true);
        }

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Text("插件库排序方式");

        if (ImGui.RadioButton("使用库分类", useSoilPluginManager))
        {
            Config.UseSoilPluginManager = true;
            Config.QueueSave();

            _ = Service<PluginManager>.Get().ReloadAllReposAsync();
        }

        if (ImGui.RadioButton("使用默认分类", !useSoilPluginManager))
        {
            Config.UseSoilPluginManager = false;
            Config.QueueSave();

            _ = Service<PluginManager>.Get().ReloadAllReposAsync();
        }

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        var receiveTest = Config.DoPluginTest;

        if (ImGui.Checkbox("接收插件测试版本", ref receiveTest))
        {
            Config.DoPluginTest = receiveTest;
            Config.QueueSave();
            
            _ = Service<PluginManager>.Get().ReloadAllReposAsync();
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey,
                                 "接收选定插件的测试版本。启用后, 当选定插件有可用的测试版更新时, 会提示更新。\n" +
                                 "在插件安装器中右键选定插件, 选择 \"接收插件测试版\" 即可为该插件启用接收测试版。");

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.TextColoredWrapped(ImGuiColors.DalamudRed,
                                 "测试版插件可能会出现不稳定、崩溃、数据丢失等情况, 请自行承担使用风险。");

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Eraser, "清除已隐藏插件"))
        {
            Config.HiddenPluginInternalName.Clear();
            Config.QueueSave();
            
            _ = Service<PluginManager>.Get().ReloadAllReposAsync();
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "清除插件安装器中所有已被隐藏的插件。");

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        var enableCharacter = Config.ProfilesEnableCharacters;
        if (ImGui.Checkbox("插件合集角色隔离", ref receiveTest))
        {
            Config.ProfilesEnableCharacters = enableCharacter;
            Config.QueueSave();
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "启用后，可将插件合集设置为仅对特定角色生效。\n此设置尚未经过充分测试，属于实验性功能，可能会导致某些插件出现问题。");
        
        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey,
                                 "Dalamud 与插件总内存占用: " + Util.FormatBytes(GC.GetTotalMemory(false)));

        ImGuiHelpers.ScaledDummy(15f);
    }

    private void DrawThirdRepoTabItem()
    {
        using var id = ImRaii.PushId("thirdRepo"u8);

        ImGui.Text("第三方插件仓库");

        if (thirdRepoListChanged)
        {
            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.HealerGreen, "[已修改]");
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey,
                                 "添加第三方插件仓库，可能导致数据丢失、游戏崩溃等，请自行承担使用风险。");

        ImGuiHelpers.ScaledDummy(15f);

        ThirdPartyRepoSettings repoToRemove = null;

        using (var table = ImRaii.Table("ThirdRepoTable", 4, ImGuiTableFlags.Borders   |
                                                             ImGuiTableFlags.RowBg     |
                                                             ImGuiTableFlags.Resizable |
                                                             ImGuiTableFlags.NoKeepColumnsVisible))
        {
            if (table)
            {
                ImGui.TableSetupColumn("#",  ImGuiTableColumnFlags.WidthFixed, 30 * ImGuiHelpers.GlobalScale);
                ImGui.TableSetupColumn("链接", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("启用", ImGuiTableColumnFlags.WidthFixed, 60 * ImGuiHelpers.GlobalScale);
                ImGui.TableSetupColumn("操作", ImGuiTableColumnFlags.WidthFixed, 40 * ImGuiHelpers.GlobalScale);

                ImGui.TableHeadersRow();

                var repoNumber = 1;

                foreach (var thirdRepoSetting in thirdRepoList)
                {
                    ImGui.TableNextRow();
                    using var repoId = ImRaii.PushId(thirdRepoSetting.Url);

                    ImGui.TableNextColumn();
                    var repoNumberStr = repoNumber.ToString();
                    var posX          = ImGui.GetCursorPosX() + (ImGui.GetColumnWidth() - ImGui.CalcTextSize(repoNumberStr).X) / 2f;
                    ImGui.SetCursorPosX(posX);
                    ImGui.Text(repoNumberStr);

                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(-1);
                    var url = thirdRepoSetting.Url;

                    if (ImGui.InputText("##thirdRepoInput", ref url, 65535, ImGuiInputTextFlags.EnterReturnsTrue))
                    {
                        var contains = thirdRepoList.Select(repo => repo.Url).Contains(url);

                        if (thirdRepoSetting.Url == url)
                        {
                            // 无变化
                        }
                        else if (contains)
                        {
                            thirdRepoAddError = "[仓库已经存在]";
                            Task.Delay(5000).ContinueWith(_ => thirdRepoAddError = string.Empty);
                        }
                        else if (!ValidThirdPartyRepoUrl(url))
                        {
                            thirdRepoAddError = "[仓库链接无效]";
                            Task.Delay(5000).ContinueWith(_ => thirdRepoAddError = string.Empty);
                        }
                        else
                        {
                            thirdRepoSetting.Url = url;
                            thirdRepoListChanged = true;
                        }
                    }

                    ImGui.TableNextColumn();
                    var isEnabled = thirdRepoSetting.IsEnabled;
                    var checkPosX = ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X - 24 * ImGuiHelpers.GlobalScale) / 2;
                    ImGui.SetCursorPosX(checkPosX);

                    if (ImGui.Checkbox("##thirdRepoCheck", ref isEnabled))
                    {
                        thirdRepoSetting.IsEnabled = isEnabled;
                        thirdRepoListChanged       = true;
                    }

                    ImGui.TableNextColumn();
                    if (ImGuiComponents.IconButton(FontAwesomeIcon.Trash))
                        repoToRemove = thirdRepoSetting;

                    repoNumber++;
                }

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGuiHelpers.CenteredText(repoNumber.ToString());

                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(-1);
                ImGui.InputText("##thirdRepoUrlInput", ref thirdRepoTempUrl, 300);

                ImGui.TableNextColumn();

                ImGui.TableNextColumn();

                if (!string.IsNullOrEmpty(thirdRepoTempUrl) && ImGuiComponents.IconButton(FontAwesomeIcon.Plus))
                {
                    thirdRepoTempUrl = thirdRepoTempUrl.TrimEnd();

                    if (thirdRepoList.Any(r => string.Equals(r.Url, thirdRepoTempUrl, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        thirdRepoAddError = "[仓库已经存在]";
                        Task.Delay(5000).ContinueWith(_ => thirdRepoAddError = string.Empty);
                    }
                    else if (!ValidThirdPartyRepoUrl(thirdRepoTempUrl))
                    {
                        thirdRepoAddError = "[仓库链接无效]";
                        Task.Delay(5000).ContinueWith(_ => thirdRepoAddError = string.Empty);
                    }
                    else
                    {
                        thirdRepoList.Add(new ThirdPartyRepoSettings
                        {
                            Url       = thirdRepoTempUrl,
                            IsEnabled = true
                        });
                        thirdRepoListChanged = true;
                        thirdRepoTempUrl     = string.Empty;
                    }
                }
            }
        }

        if (repoToRemove != null)
        {
            thirdRepoList.Remove(repoToRemove);
            thirdRepoListChanged = true;
        }

        if (!string.IsNullOrEmpty(thirdRepoAddError))
            ImGui.TextColoredWrapped(ImGuiColors.DalamudRed, thirdRepoAddError);

        ImGuiHelpers.ScaledDummy(15f);

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(15f);

        var addPresetRepos = Config.AddPresetThirdRepos;

        if (ImGui.Checkbox("添加预置第三方插件仓库", ref addPresetRepos))
        {
            Config.AddPresetThirdRepos = addPresetRepos;
            Config.QueueSave();
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey,
                                 "添加一批来自 Dalamud (Soil) 相关人员维护的第三方插件仓库");

        ImGuiHelpers.ScaledDummy(15f);
    }

    private void DrawLocalPluginTabItem()
    {
        using var id = ImRaii.PushId("devPluginLocation"u8);

        ImGui.Text("本地插件");

        if (devPluginLocationsChanged)
        {
            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.HealerGreen, "[已修改]");
        }

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey,
                                 "添加本地插件，必须为 .dll 文件。");

        ImGuiHelpers.ScaledDummy(15f);

        if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Folder, "选择本地插件 (.dll)"))
        {
            fileDialogManager.OpenFileDialog(
                "选择本地插件 (.dll)",
                ".dll",
                (result, path) =>
                {
                    if (result)
                    {
                        devPluginTempLocation = path;
                        AddDevPlugin();
                    }
                });
        }

        DevPluginLocationSettings locationToRemove = null;

        using (var table = ImRaii.Table("DevPluginTable",
                                        4,
                                        ImGuiTableFlags.Borders   |
                                        ImGuiTableFlags.RowBg     |
                                        ImGuiTableFlags.Resizable |
                                        ImGuiTableFlags.NoKeepColumnsVisible))
        {
            if (table)
            {
                ImGui.TableSetupColumn("#",  ImGuiTableColumnFlags.WidthFixed, 30 * ImGuiHelpers.GlobalScale);
                ImGui.TableSetupColumn("路径", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("启用", ImGuiTableColumnFlags.WidthFixed, 60 * ImGuiHelpers.GlobalScale);
                ImGui.TableSetupColumn("操作", ImGuiTableColumnFlags.WidthFixed, 40 * ImGuiHelpers.GlobalScale);

                ImGui.TableHeadersRow();

                var locNumber = 1;

                foreach (var devPluginLocationSetting in devPluginLocations)
                {
                    using var localID = ImRaii.PushId(devPluginLocationSetting.Path);

                    ImGui.TableNextRow();

                    ImGui.TableNextColumn();
                    var locNumberStr = locNumber.ToString();
                    var posX         = ImGui.GetCursorPosX() + (ImGui.GetColumnWidth() - ImGui.CalcTextSize(locNumberStr).X) / 2f;
                    ImGui.SetCursorPosX(posX);
                    ImGui.Text(locNumberStr);

                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(-1);
                    var path = devPluginLocationSetting.Path;

                    if (ImGui.InputText("##devPluginLocationInput", ref path, 65535, ImGuiInputTextFlags.EnterReturnsTrue))
                    {
                        var contains = devPluginLocations.Select(loc => loc.Path).Contains(path);

                        if (devPluginLocationSetting.Path == path)
                        {
                            // 无变化
                        }
                        else if (contains)
                        {
                            devPluginLocationAddError = "[路径已存在]";
                            Task.Delay(5000).ContinueWith(_ => devPluginLocationAddError = string.Empty);
                        }
                        else if (!ValidDevPluginPath(path))
                        {
                            devPluginLocationAddError = "[路径无效]";
                            Task.Delay(5000).ContinueWith(_ => devPluginLocationAddError = string.Empty);
                        }
                        else
                        {
                            devPluginLocationSetting.Path = path;
                            devPluginLocationsChanged     = true;
                        }
                    }

                    ImGui.TableNextColumn();
                    var isEnabled = devPluginLocationSetting.IsEnabled;
                    var checkPosX = ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X - 24 * ImGuiHelpers.GlobalScale) / 2;
                    ImGui.SetCursorPosX(checkPosX);

                    if (ImGui.Checkbox("##devPluginLocationCheck", ref isEnabled))
                    {
                        devPluginLocationSetting.IsEnabled = isEnabled;
                        devPluginLocationsChanged          = true;
                    }

                    ImGui.TableNextColumn();
                    if (ImGuiComponents.IconButton(FontAwesomeIcon.Trash))
                        locationToRemove = devPluginLocationSetting;

                    locNumber++;
                }

                ImGui.TableNextRow();

                ImGui.TableNextColumn();
                var lastNumStr = locNumber.ToString();
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetColumnWidth() - ImGui.CalcTextSize(lastNumStr).X) / 2f);
                ImGui.Text(lastNumStr);

                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(-1);
                ImGui.InputText("##devPluginLocationInputNew", ref devPluginTempLocation, 300);

                ImGui.TableNextColumn();

                ImGui.TableNextColumn();
                if (!string.IsNullOrEmpty(devPluginTempLocation) && ImGuiComponents.IconButton(FontAwesomeIcon.Plus))
                    AddDevPlugin();
            }
        }

        if (locationToRemove != null)
        {
            devPluginLocations.Remove(locationToRemove);
            devPluginLocationsChanged = true;
        }

        if (!string.IsNullOrEmpty(devPluginLocationAddError))
            ImGui.TextColoredWrapped(ImGuiColors.DalamudRed, devPluginLocationAddError);
    }

    private void DrawAutoUpdateTabItem()
    {
        ImGui.TextColoredWrapped(ImGuiColors.DalamudWhite, "Dalamud 支持自动更新插件, 确保用户能及时获取最新功能和错误修复. 可在此设置自动更新的时机和方式");
        ImGuiHelpers.ScaledDummy(2);

        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "用户始终可通过插件列表中的更新按钮手动更新插件. 也可右键单击插件并选择\"始终自动更新\"为特定插件启用自动更新");
        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "Dalamud 仅在处于空闲状态时通知更新");

        ImGuiHelpers.ScaledDummy(8);

        ImGui.TextColoredWrapped(ImGuiColors.DalamudWhite, "当游戏启动时...");
        var behaviorInt = (int)behavior;
        ImGui.RadioButton("不自动检查更新",  ref behaviorInt, (int)AutoUpdateBehavior.None);
        ImGui.RadioButton("仅通知新更新",   ref behaviorInt, (int)AutoUpdateBehavior.OnlyNotify);
        ImGui.RadioButton("自动更新主库插件", ref behaviorInt, (int)AutoUpdateBehavior.UpdateMainRepo);
        ImGui.RadioButton("自动更新所有插件", ref behaviorInt, (int)AutoUpdateBehavior.UpdateAll);
        behavior = (AutoUpdateBehavior)behaviorInt;

        if (behavior == AutoUpdateBehavior.UpdateAll)
        {
            ImGui.TextColoredWrapped(ImGuiColors.DalamudOrange,
                                     "警告: 此选项将更新所有插件, 包括非主库来源的插件\n" +
                                     "这些更新未经 Dalamud 团队审核, 可能包含恶意代码");
        }

        ImGuiHelpers.ScaledDummy(8);

        ImGui.Checkbox("自动更新被禁用的插件",   ref updateDisabledPlugins);
        ImGui.Checkbox("在聊天栏显示可用更新通知", ref chatNotification);
        ImGui.Checkbox("游戏运行时定期检查更新",  ref checkPeriodically);
        ImGui.TextColoredWrapped(ImGuiColors.DalamudGrey, "启动后不会自动更新插件, 仅在用户未活跃游戏时接收通知");

        ImGuiHelpers.ScaledDummy(5);
        ImGui.Separator();
        ImGuiHelpers.ScaledDummy(5);

        ImGui.TextColoredWrapped(ImGuiColors.DalamudWhite, "插件单独设置");

        ImGui.TextColoredWrapped(ImGuiColors.DalamudWhite, "在此可为特定插件单独设置是否接收更新, 此设置将覆盖上述全局设置");

        if (autoUpdatePreferences.Count == 0)
        {
            ImGuiHelpers.ScaledDummy(20);

            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudGrey))
            {
                ImGuiHelpers.CenteredText("尚未为任何插件配置自动更新规则");
            }

            ImGuiHelpers.ScaledDummy(2);
        }
        else
        {
            ImGuiHelpers.ScaledDummy(5);

            var pic = Service<PluginImageCache>.Get();

            var   windowSize           = ImGui.GetWindowSize();
            var   pluginLineHeight     = 32 * ImGuiHelpers.GlobalScale;
            Guid? wantRemovePluginGuid = null;

            foreach (var preference in autoUpdatePreferences)
            {
                var pmPlugin = Service<PluginManager>.Get().InstalledPlugins
                                                     .FirstOrDefault(x => x.EffectiveWorkingPluginId == preference.WorkingPluginId);

                const int btnOffset = 2;

                if (pmPlugin != null)
                {
                    var cursorBeforeIcon = ImGui.GetCursorPos();
                    pic.TryGetIcon(pmPlugin, pmPlugin.Manifest, pmPlugin.IsThirdParty, out var icon, out _);
                    icon ??= pic.DefaultIcon;

                    ImGui.Image(icon.Handle, new Vector2(pluginLineHeight));

                    if (pmPlugin.IsDev)
                    {
                        ImGui.SetCursorPos(cursorBeforeIcon);

                        using (ImRaii.PushStyle(ImGuiStyleVar.Alpha, 0.7f))
                        {
                            ImGui.Image(pic.DevPluginIcon.Handle, new Vector2(pluginLineHeight));
                        }
                    }

                    ImGui.SameLine();

                    var text       = $"{pmPlugin.Name}{(pmPlugin.IsDev ? " (开发版插件)" : string.Empty)}";
                    var textHeight = ImGui.CalcTextSize(text);
                    var before     = ImGui.GetCursorPos();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + pluginLineHeight / 2 - textHeight.Y / 2);
                    ImGui.Text(text);

                    ImGui.SetCursorPos(before);
                }
                else
                {
                    ImGui.Image(pic.DefaultIcon.Handle, new Vector2(pluginLineHeight));
                    ImGui.SameLine();

                    const string text       = "未知插件";
                    var          textHeight = ImGui.CalcTextSize(text);
                    var          before     = ImGui.GetCursorPos();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + pluginLineHeight / 2 - textHeight.Y / 2);
                    ImGui.Text(text);

                    ImGui.SetCursorPos(before);
                }

                ImGui.SameLine();
                ImGui.SetCursorPosX(windowSize.X                                 - ImGuiHelpers.GlobalScale * 320);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + pluginLineHeight / 2 - ImGui.GetFrameHeight()   / 2);

                ImGui.SetNextItemWidth(ImGuiHelpers.GlobalScale * 250);

                using (var combo = ImRaii.Combo($"###autoUpdateBehavior{preference.WorkingPluginId}", OptKindToString(preference.Kind)))
                {
                    if (combo.Success)
                    {
                        foreach (var kind in Enum.GetValues<AutoUpdatePreference.OptKind>())
                        {
                            if (ImGui.Selectable(OptKindToString(kind)))
                                preference.Kind = kind;
                        }
                    }
                }

                ImGui.SameLine();
                ImGui.SetCursorPosX(windowSize.X                                 - ImGuiHelpers.GlobalScale * 30 * btnOffset - 5);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + pluginLineHeight / 2 - ImGui.GetFrameHeight()   / 2);

                if (ImGuiComponents.IconButton($"###removePlugin{preference.WorkingPluginId}", FontAwesomeIcon.Trash))
                    wantRemovePluginGuid = preference.WorkingPluginId;

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("移除规则");

                continue;

                string OptKindToString(AutoUpdatePreference.OptKind kind)
                {
                    return kind switch
                    {
                        AutoUpdatePreference.OptKind.NeverUpdate  => "从不更新",
                        AutoUpdatePreference.OptKind.AlwaysUpdate => "总是更新",
                        _                                         => throw new ArgumentOutOfRangeException()
                    };
                }
            }

            if (wantRemovePluginGuid != null)
                autoUpdatePreferences.RemoveAll(x => x.WorkingPluginId == wantRemovePluginGuid);
        }

        var pickerId = DalamudComponents.DrawPluginPicker(
            "###autoUpdatePicker", ref pickerSearch, OnPluginPicked, IsPluginDisabled, IsPluginFiltered);

        const FontAwesomeIcon addButtonIcon = FontAwesomeIcon.Plus;
        const string          addButtonText = "添加规则";
        ImGuiHelpers.CenterCursorFor(ImGuiComponents.GetIconButtonWithTextWidth(addButtonIcon, addButtonText));

        if (ImGuiComponents.IconButtonWithText(addButtonIcon, addButtonText))
        {
            pickerSearch = string.Empty;
            ImGui.OpenPopup(pickerId);
        }

        return;

        void OnPluginPicked(LocalPlugin plugin)
        {
            var id = plugin.EffectiveWorkingPluginId;
            if (id == Guid.Empty)
                throw new InvalidOperationException("Plugin ID 为空");

            autoUpdatePreferences.Add(new AutoUpdatePreference(id));
        }

        bool IsPluginDisabled(LocalPlugin plugin)
        {
            return autoUpdatePreferences.Any(x => x.WorkingPluginId == plugin.EffectiveWorkingPluginId);
        }

        bool IsPluginFiltered(LocalPlugin plugin)
        {
            return !plugin.IsDev;
        }
    }
}
