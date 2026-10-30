using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Player;
using Dalamud.Game.Text.SeStringHandling;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Internal.DesignSystem;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Internal;
using Dalamud.Plugin.Internal.Profiles;
using Serilog;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// ImGui widget used to manage profiles.
/// </summary>
internal class ProfileManagerWidget
{
    private readonly PluginInstallerWindow installer;
    private          Mode                  mode = Mode.Overview;
    private          Guid?                 editingProfileGuid;
    private          bool                  lastWasPickingPlugin;

    private string pickerSearch    = string.Empty;
    private string profileNameEdit = string.Empty;

    /// <summary>
    /// Initializes a new instance of the <see cref="ProfileManagerWidget"/> class.
    /// </summary>
    /// <param name="installer">The plugin installer.</param>
    public ProfileManagerWidget
    (
        PluginInstallerWindow installer
    ) => this.installer = installer;

    private enum Mode
    {
        Overview,
        EditSingleProfile
    }

    /// <summary>
    /// Draw this widget's contents.
    /// </summary>
    public void Draw()
    {
        if (!Service<DalamudConfiguration>.Get().ProfilesEnabled)
        {
            DrawChoice();
            return;
        }

        const string TUTORIAL_TITLE = "关于插件合集" + "###collectionsTutorWindow";
        var          tutorialId     = ImGui.GetID(TUTORIAL_TITLE);
        DrawTutorial(TUTORIAL_TITLE);

        switch (this.mode)
        {
            case Mode.Overview:
                this.DrawOverview(tutorialId);
                break;

            case Mode.EditSingleProfile:
                this.DrawEdit();
                break;
        }
    }

    /// <summary>
    /// Reset the widget.
    /// </summary>
    public void Reset()
    {
        this.mode               = Mode.Overview;
        this.editingProfileGuid = null;
        this.pickerSearch       = string.Empty;
    }

    private static void DrawChoice()
    {
        ImGuiHelpers.ScaledDummy(60);
        ImGuiHelpers.CenteredText("插件合集可将多个插件分组，以便统一启用、禁用和分享。");
        ImGuiHelpers.CenteredText("此功能仍处于试验阶段，可能存在问题。是否启用？");
        ImGuiHelpers.ScaledDummy(20);

        var buttonWidth = ImGui.GetWindowWidth() / 3;
        ImGuiHelpers.CenterCursorFor((int)buttonWidth);

        if (ImGui.Button("启用插件合集", new Vector2(buttonWidth, 40 * ImGuiHelpers.GlobalScale)))
        {
            var config = Service<DalamudConfiguration>.Get();
            config.ProfilesEnabled = true;
            config.QueueSave();
        }
    }

    private static void DrawTutorial
    (
        string modalTitle
    )
    {
        var open = true;
        ImGui.SetNextWindowSize(new Vector2(650, 550), ImGuiCond.Appearing);

        using (var popup = ImRaii.PopupModal(modalTitle, ref open))
        {
            if (popup)
            {
                var       buttonHeight = ImGui.GetFrameHeight() + (ImGui.GetStyle().ItemSpacing.Y * 2);
                using var scrolling    = ImRaii.Child("###scrolling"u8, new Vector2(-1, ImGui.GetContentRegionAvail().Y - buttonHeight));

                if (scrolling)
                {
                    ImGui.TextWrapped("合集是可分享的插件列表，可通过插件安装器或聊天指令启用、禁用。\n合集启用时，其中处于激活状态的插件也会启用。插件若属于多个合集，只要任一合集需要它，它就会保持启用。");
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.TextWrapped("编辑合集时，可点击加号添加插件；也可在“已安装插件”页面点击工具箱图标，将插件加入合集。");
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.TextWrapped("若将合集的启动行为设为“启动时始终启用”，每次启动游戏时都会启用此合集及其中的插件，即使上次游戏期间曾手动禁用。");
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.TextWrapped("合集内每个插件旁的复选框表示该插件是否在此合集中激活。未勾选时，此合集不会启用该插件；但其他合集仍可能将其启用。");
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.TextWrapped("勾选“仅对指定角色启用”后，合集只会在指定角色上激活。可点击加号选择角色，或点击人物图标添加当前角色，以便为不同角色使用不同合集。");
                    ImGuiHelpers.ScaledDummy(5);
                    ImGui.TextWrapped("可在聊天窗口或宏中使用以下指令管理合集：");

                    ImGui.Bullet();
                    ImGui.SameLine();
                    ImGui.TextWrapped($"{PluginManagementCommandHandler.CommandEnableProfile} \"合集名称\" —— 启用合集");

                    ImGui.Bullet();
                    ImGui.SameLine();
                    ImGui.TextWrapped($"{PluginManagementCommandHandler.CommandDisableProfile} \"合集名称\" —— 禁用合集");

                    ImGui.Bullet();
                    ImGui.SameLine();
                    ImGui.TextWrapped($"{PluginManagementCommandHandler.CommandToggleProfile} \"合集名称\" —— 切换合集状态");

                    ImGui.TextWrapped("执行多条指令时，将按顺序处理。");
                }

                ImGuiHelpers.ScaledDummy(4);
                const float BUTTON_WIDTH = 120f;
                ImGui.SetCursorPosX((ImGui.GetWindowWidth() - BUTTON_WIDTH) / 2);

                if (ImGui.Button("OK"u8, new Vector2(BUTTON_WIDTH, 0)))
                {
                    ImGui.CloseCurrentPopup();
                }
            }
        }

        var config = Service<DalamudConfiguration>.Get();

        if (!config.ProfilesHasSeenTutorial)
        {
            ImGui.OpenPopup(modalTitle);
            config.ProfilesHasSeenTutorial = true;
            config.QueueSave();
        }
    }

    private void DrawOverview
    (
        uint tutorialId
    )
    {
        var didAny  = false;
        var profman = Service<ProfileManager>.Get();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Plus))
            profman.AddNewProfile();

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("添加合集");

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.FileImport))
        {
            try
            {
                profman.ImportProfile(ImGui.GetClipboardText());
                Service<NotificationManager>.Get().AddNotification("合集导入成功", type: NotificationType.Success);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Could not import profile");
                Service<NotificationManager>.Get().AddNotification("无法导入合集", type: NotificationType.Error);
            }
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("从剪贴板导入分享的合集");

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Question))
            ImGui.OpenPopup(tutorialId);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("了解插件合集");

        ImGui.Separator();
        ImGuiHelpers.ScaledDummy(5);

        using var profileChooserChild = ImRaii.Child("###profileChooserScrolling"u8);

        if (profileChooserChild)
        {
            var   contentRegionMaxX = ImGui.GetWindowContentRegionMax().X;
            Guid? toCloneGuid       = null;

            using var syncScope = profman.GetSyncScope();

            foreach (var profile in profman.Profiles)
            {
                if (profile.IsDefaultProfile)
                    continue;

                var isEnabled = profile.IsEnabled;

                if (ImGuiComponents.ToggleButton($"###toggleButton{profile.Guid}", ref isEnabled))
                {
                    Task.Run(() => profile.SetStateAsync(isEnabled))
                        .ContinueWith(this.installer.DisplayErrorContinuation, "无法更改插件状态");
                }

                ImGui.SameLine();
                ImGuiHelpers.ScaledDummy(3);
                ImGui.SameLine();

                // Center text in frame height
                var textHeight = ImGui.CalcTextSize(profile.Name);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (ImGui.GetFrameHeight() / 2) - (textHeight.Y / 2));
                ImGui.Text(profile.Name);

                ImGui.SameLine();
                ImGui.SetCursorPosX(contentRegionMaxX - (ImGuiHelpers.GlobalScale * 30));

                if (ImGuiComponents.IconButton($"###editButton{profile.Guid}", FontAwesomeIcon.PencilAlt))
                {
                    this.mode               = Mode.EditSingleProfile;
                    this.editingProfileGuid = profile.Guid;
                    this.profileNameEdit    = profile.Name;
                }

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("编辑此合集");

                ImGui.SameLine();
                ImGui.SetCursorPosX(contentRegionMaxX - (ImGuiHelpers.GlobalScale * 30 * 2) - 5);

                if (ImGuiComponents.IconButton($"###cloneButton{profile.Guid}", FontAwesomeIcon.Copy))
                    toCloneGuid = profile.Guid;

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("复制此合集");

                ImGui.SameLine();
                ImGui.SetCursorPosX(contentRegionMaxX - (ImGuiHelpers.GlobalScale * 30 * 3) - 5);

                if (ImGuiComponents.IconButton($"###exportButton{profile.Guid}", FontAwesomeIcon.FileExport))
                {
                    ImGui.SetClipboardText(profile.Model.SerializeForShare());
                    Service<NotificationManager>.Get().AddNotification("合集已复制到剪贴板", type: NotificationType.Success);
                }

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("将合集复制到剪贴板以便分享");

                didAny = true;

                ImGuiHelpers.ScaledDummy(2);

                // Separator if not the last item
                if (profile != profman.Profiles.Last())
                {
                    // Very light grey
                    ImGui.PushStyleColor(ImGuiCol.Border, ImGuiColors.DalamudGrey.WithAlpha(0.2f));
                    ImGui.Separator();
                    ImGui.PopStyleColor();

                    ImGuiHelpers.ScaledDummy(2);
                }
            }

            if (toCloneGuid != null)
            {
                profman.CloneProfile(profman.Profiles.First(x => x.Guid == toCloneGuid));
            }

            if (!didAny)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.DalamudGrey);
                ImGuiHelpers.CenteredText("尚无合集，点击添加");
                ImGui.PopStyleColor();
            }
        }
    }

    private void DrawEdit()
    {
        if (this.editingProfileGuid == null)
        {
            Log.Error("Editing profile guid was null");
            this.Reset();
            return;
        }

        var profman = Service<ProfileManager>.Get();
        var pm      = Service<PluginManager>.Get();
        var pic     = Service<PluginImageCache>.Get();
        var profile = profman.Profiles.FirstOrDefault(x => x.Guid == this.editingProfileGuid);

        if (profile == null)
        {
            Log.Error("Could not find profile {Guid} for edit", this.editingProfileGuid);
            this.Reset();
            return;
        }

        var addPluginToProfilePopupId = DalamudComponents.DrawPluginPicker
        (
            "###addPluginToProfilePicker",
            ref this.pickerSearch,
            plugin =>
            {
                Task.Run(() => profile.AddOrUpdateAsync(plugin.EffectiveWorkingPluginId, plugin.Manifest.InternalName, true, false))
                    .ContinueWith(this.installer.DisplayErrorContinuation, "无法更改插件状态");
            },
            plugin => !plugin.Manifest.SupportsProfiles ||
                      profile.Plugins.Any(x => x.WorkingPluginId == plugin.EffectiveWorkingPluginId),
            getAnnotation: plugin =>
            {
                var count = profman.Profiles.Count
                (p => !p.IsDefaultProfile               &&
                      p.Guid != this.editingProfileGuid &&
                      p.Plugins.Any(x => x.WorkingPluginId == plugin.EffectiveWorkingPluginId)
                );
                return count switch
                {
                    0 => null,
                    1 => "（另属 1 个合集）",
                    _ => $"（另属 {count} 个合集）"
                };
            }
        );

        // Reapply states when closing plugin picker, as we might have changed want states for some plugins. Only do this when closing, to avoid doing it multiple times while picking.
        var isPickingPlugin = ImGui.IsPopupOpen("###addPluginToProfilePicker");

        switch (isPickingPlugin)
        {
            case false when this.lastWasPickingPlugin:
                // Clear search after closing
                this.pickerSearch = string.Empty;

                Task.Run(async () => { await profman.ApplyAllWantStatesAsync("Finish adding plugins"); })
                    .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });

                this.lastWasPickingPlugin = false;
                break;

            case true:
                this.lastWasPickingPlugin = true;
                break;
        }

        var didAny = false;

        // ======== Top bar ========
        var windowSize = ImGui.GetWindowSize();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.ArrowLeft))
            this.Reset();

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("返回总览");

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.FileExport))
        {
            ImGui.SetClipboardText(profile.Model.SerializeForShare());
            Service<NotificationManager>.Get().AddNotification("合集已复制到剪贴板", type: NotificationType.Success);
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("将合集复制到剪贴板以便分享");

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Trash))
        {
            this.Reset();

            // DeleteProfile() is sync, it doesn't apply and we are modifying the plugins collection. Will throw below when iterating
            // TODO: DeleteProfileAsync should probably apply as well
            Task.Run
                (async () =>
                    {
                        await profman.DeleteProfileAsync(profile);
                        await profman.ApplyAllWantStatesAsync("Delete profile");
                    }
                )
                .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("删除此合集");

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        ImGui.SetNextItemWidth(windowSize.X / 3);

        if (ImGui.InputText("###profileNameInput"u8, ref this.profileNameEdit, 255))
        {
            profile.Name = this.profileNameEdit;
        }

        ImGui.SameLine();
        ImGui.SetCursorPosX(windowSize.X - (ImGui.GetFrameHeight() * 1.55f * ImGuiHelpers.GlobalScale));

        var isEnabled = profile.IsEnabled;

        if (ImGuiComponents.ToggleButton($"###toggleButton{profile.Guid}", ref isEnabled))
        {
            Task.Run(() => profile.SetStateAsync(isEnabled))
                .ContinueWith(this.installer.DisplayErrorContinuation, "无法更改插件状态");
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("启用或禁用此合集");

        ImGui.Separator();

        ImGuiHelpers.ScaledDummy(5);

        ImGui.Text("启动行为");

        if (ImGui.BeginCombo
            (
                "##startupBehaviorPicker"u8,
                profile.StartupPolicy switch
                {
                    ProfileModelV1.ProfileStartupPolicy.RememberState => "记住上次状态",
                    ProfileModelV1.ProfileStartupPolicy.AlwaysEnable => "启动时始终启用",
                    ProfileModelV1.ProfileStartupPolicy.AlwaysDisable => "启动时始终禁用",
                    _ => throw new ArgumentOutOfRangeException(nameof(profile.StartupPolicy), profile.StartupPolicy, null)
                }
            ))
        {
            foreach (var policy in Enum.GetValues<ProfileModelV1.ProfileStartupPolicy>())
            {
                var name = policy switch
                {
                    ProfileModelV1.ProfileStartupPolicy.RememberState => "记住上次状态",
                    ProfileModelV1.ProfileStartupPolicy.AlwaysEnable  => "启动时始终启用",
                    ProfileModelV1.ProfileStartupPolicy.AlwaysDisable => "启动时始终禁用",
                    _                                                 => throw new ArgumentOutOfRangeException(nameof(policy), policy, null)
                };

                if (ImGui.Selectable(name, profile.StartupPolicy == policy))
                {
                    profile.StartupPolicy = policy;
                }
            }

            ImGui.EndCombo();
        }

        ImGuiHelpers.ScaledDummy(5);

        var model = (ProfileModelV1)profile.Model;

        var enableForCharacters = model.EnableForCharacters;
        ImGui.Checkbox
        (
            "仅对指定角色启用",
            ref enableForCharacters
        );

        if (enableForCharacters != model.EnableForCharacters)
        {
            model.EnableForCharacters = enableForCharacters;
            Service<DalamudConfiguration>.Get().QueueSave();

            // Profile might now no longer want active
            Task.Run(async () => { await profman.ApplyAllWantStatesAsync("Toggle enable for characters"); })
                .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });
        }

        // If the profile is configured to enable by specific characters, show the character list and controls
        if (model.EnableForCharacters)
        {
            ulong? wantRemoveContentId = null;

            if (model.EnabledCharacters.Count == 0)
            {
                ImGui.TextColoredWrapped
                (
                    ImGuiColors.DalamudGrey,
                    "尚未指定角色。请使用下方按钮添加，否则此合集不会对任何角色启用。"
                );
            }
            else if (ImGui.BeginTable
                     (
                         "###charFilterTable",
                         2,
                         ImGuiTableFlags.RowBg | ImGuiTableFlags.SizingFixedFit
                     ))
            {
                ImGui.TableSetupColumn("###remove"u8,   ImGuiTableColumnFlags.WidthFixed);
                ImGui.TableSetupColumn("###charname"u8, ImGuiTableColumnFlags.WidthStretch);

                foreach (var entry in model.EnabledCharacters.ToArray())
                {
                    ImGui.TableNextRow();

                    ImGui.TableSetColumnIndex(0);
                    if (ImGuiComponents.IconButton($"###removeChar{entry.ContentId}", FontAwesomeIcon.Trash))
                        wantRemoveContentId = entry.ContentId;

                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("移除角色");

                    ImGui.TableSetColumnIndex(1);
                    string characterDisplay;
                    if (!string.IsNullOrEmpty(entry.DisplayName) && !string.IsNullOrEmpty(entry.ServerName))
                        characterDisplay = $"{entry.DisplayName} <icon({(int)BitmapFontIcon.CrossWorld})> {entry.ServerName}";
                    else
                        characterDisplay = entry.ContentId.ToString();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (ImGui.GetFrameHeight() / 2f) - (ImGui.GetTextLineHeight() / 2f));
                    ImGuiHelpers.CompileSeStringWrapped(characterDisplay);
                }

                ImGui.EndTable();
            }

            if (wantRemoveContentId != null)
            {
                var toRem = model.EnabledCharacters.FirstOrDefault(x => x.ContentId == wantRemoveContentId.Value);

                if (toRem != null)
                {
                    model.EnabledCharacters.Remove(toRem);
                    Service<DalamudConfiguration>.Get().QueueSave();
                }

                // Profile might now no longer want active
                Task.Run(async () => { await profman.ApplyAllWantStatesAsync("Remove character"); })
                    .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });
            }

            ImGuiHelpers.ScaledDummy(5);

            var player = Service<PlayerState>.Get();

            if (player.IsLoaded)
            {
                using var disabled = ImRaii.Disabled(model.EnabledCharacters.Any(x => x.ContentId == player.ContentId));

                if (ImGuiComponents.IconButtonWithText(FontAwesomeIcon.Plus, $"Add current character: {player.CharacterName}"))
                {
                    var serverName = player.HomeWorld.Value.Name.ExtractText();
                    model.EnabledCharacters.Add(new ProfileModelV1.ProfileModelV1Character(player.CharacterName, player.ContentId, serverName));
                    Service<DalamudConfiguration>.Get().QueueSave();

                    // Profile might now want active
                    Task.Run(async () => { await profman.ApplyAllWantStatesAsync("Add character"); })
                        .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });
                }
            }
            else
            {
                ImGui.TextColored(ImGuiColors.DalamudGrey, "请先登录角色，再添加当前角色。");
            }

            ImGuiHelpers.ScaledDummy(5);
        }

        ImGui.Separator();
        var wantPluginAddPopup = false;

        using var pluginListChild = ImRaii.Child("###profileEditorPluginList"u8);

        if (pluginListChild)
        {
            var   contentRegionMaxX    = ImGui.GetWindowContentRegionMax().X;
            var   pluginLineHeight     = 32 * ImGuiHelpers.GlobalScale;
            Guid? wantRemovePluginGuid = null;

            using var syncScope = profile.GetSyncScope();

            foreach (var profileEntry in profile.Plugins.ToArray())
            {
                didAny = true;
                var pmPlugin  = pm.InstalledPlugins.FirstOrDefault(x => x.EffectiveWorkingPluginId == profileEntry.WorkingPluginId);
                var btnOffset = 2;

                if (pmPlugin != null)
                {
                    var cursorBeforeIcon = ImGui.GetCursorPos();
                    pic.TryGetIcon(pmPlugin, pmPlugin.Manifest, pmPlugin.IsThirdParty, out var icon, out _);
                    icon ??= pic.DefaultIcon;

                    ImGui.Image(icon.Handle, new Vector2(pluginLineHeight));

                    if (pmPlugin.IsDev)
                    {
                        ImGui.SetCursorPos(cursorBeforeIcon);
                        ImGui.PushStyleVar(ImGuiStyleVar.Alpha, 0.7f);
                        ImGui.Image(pic.DevPluginIcon.Handle, new Vector2(pluginLineHeight));
                        ImGui.PopStyleVar();
                    }

                    ImGui.SameLine();
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (5 * ImGuiHelpers.GlobalScale));

                    var text       = $"{pmPlugin.Name}{(pmPlugin.IsDev ? " (dev plugin" : string.Empty)}";
                    var textHeight = ImGui.CalcTextSize(text);
                    var before     = ImGui.GetCursorPos();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (pluginLineHeight / 2) - (textHeight.Y / 2));
                    ImGui.Text(text);

                    ImGui.SetCursorPos(before);
                }
                else
                {
                    ImGui.Image(pic.DefaultIcon.Handle, new Vector2(pluginLineHeight));
                    ImGui.SameLine();

                    var text       = $"{profileEntry.InternalName}（未安装）";
                    var textHeight = ImGui.CalcTextSize(text);
                    var before     = ImGui.GetCursorPos();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (pluginLineHeight / 2) - (textHeight.Y / 2));
                    ImGui.Text(text);

                    var firstAvailableInstalled = pm.InstalledPlugins.FirstOrDefault(x => x.InternalName == profileEntry.InternalName);
                    var installable =
                        pm.AvailablePlugins.FirstOrDefault(x => x.InternalName == profileEntry.InternalName && !x.SourceRepo.IsThirdParty);

                    if (firstAvailableInstalled != null)
                    {
                        ImGui.Text($"Match to plugin '{firstAvailableInstalled.Name}'?");
                        ImGui.SameLine();

                        if (ImGuiComponents.IconButtonWithText
                            (
                                FontAwesomeIcon.Check,
                                "Yes, use this one"
                            ))
                        {
                            profileEntry.WorkingPluginId = firstAvailableInstalled.EffectiveWorkingPluginId;
                            Task.Run(async () => { await profman.ApplyAllWantStatesAsync("Match plugin"); })
                                .ContinueWith(t => { this.installer.DisplayErrorContinuation(t, "无法更改插件状态"); });
                        }
                    }
                    else if (installable != null)
                    {
                        ImGui.SameLine();
                        ImGui.SetCursorPosX(contentRegionMaxX                              - (ImGuiHelpers.GlobalScale * 30 * 2) - 2);
                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (pluginLineHeight / 2) - (ImGui.GetFrameHeight()   / 2));
                        btnOffset = 3;

                        if (ImGuiComponents.IconButton($"###installMissingPlugin{installable.InternalName}", FontAwesomeIcon.Download))
                        {
                            this.installer.StartInstall(installable, false);
                        }

                        if (ImGui.IsItemHovered())
                            ImGui.SetTooltip("安装此插件");
                    }

                    ImGui.SetCursorPos(before);
                }

                ImGui.SameLine();
                ImGui.SetCursorPosX(contentRegionMaxX                              - (ImGuiHelpers.GlobalScale * 30));
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (pluginLineHeight / 2) - (ImGui.GetFrameHeight()   / 2));

                var enabled = profileEntry.IsEnabled;

                if (ImGui.Checkbox($"###{this.editingProfileGuid}-{profileEntry.InternalName}", ref enabled))
                {
                    Task.Run(() => profile.AddOrUpdateAsync(profileEntry.WorkingPluginId, profileEntry.InternalName, enabled))
                        .ContinueWith(this.installer.DisplayErrorContinuation, "无法更改插件状态");
                }

                ImGui.SameLine();
                ImGui.SetCursorPosX(contentRegionMaxX                              - (ImGuiHelpers.GlobalScale * 30 * btnOffset) - 5);
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (pluginLineHeight / 2) - (ImGui.GetFrameHeight()   / 2));

                if (ImGuiComponents.IconButton($"###removePlugin{profileEntry.InternalName}", FontAwesomeIcon.Trash))
                {
                    wantRemovePluginGuid = profileEntry.WorkingPluginId;
                }

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("从此合集中移除插件");

                // Separator if not the last item
                if (profileEntry != profile.Plugins.Last())
                {
                    // Very light grey
                    ImGui.PushStyleColor(ImGuiCol.Border, ImGuiColors.DalamudGrey.WithAlpha(0.2f));
                    ImGui.Separator();
                    ImGui.PopStyleColor();
                }
            }

            if (wantRemovePluginGuid != null)
            {
                // TODO: handle error
                Task.Run(() => profile.RemoveAsync(wantRemovePluginGuid.Value))
                    .ContinueWith(this.installer.DisplayErrorContinuation, "无法移除插件");
            }

            if (!didAny)
            {
                ImGui.TextColored(ImGuiColors.DalamudGrey, "此合集尚无插件");
            }

            ImGuiHelpers.ScaledDummy(10);

            const string ADD_PLUGINS_TEXT = "添加插件";
            ImGuiHelpers.CenterCursorFor((int)(ImGui.CalcTextSize(ADD_PLUGINS_TEXT).X + 30 + (ImGuiHelpers.GlobalScale * 5)));

            if (ImGuiComponents.IconButton(FontAwesomeIcon.Plus))
                wantPluginAddPopup = true;

            ImGui.SameLine();
            ImGuiHelpers.ScaledDummy(5);
            ImGui.SameLine();

            ImGui.Text(ADD_PLUGINS_TEXT);

            ImGuiHelpers.ScaledDummy(10);
        }

        if (wantPluginAddPopup)
        {
            this.pickerSearch = string.Empty;
            ImGui.OpenPopup(addPluginToProfilePopupId);
        }
    }
}
