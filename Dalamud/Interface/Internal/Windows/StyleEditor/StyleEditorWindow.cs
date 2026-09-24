using System.Linq;
using System.Numerics;
using System.Reflection;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Player;
using Dalamud.Game.Text.SeStringHandling;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.Internal.DesignSystem;
using Dalamud.Interface.Style;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Interface.Windowing;
using Dalamud.Utility;
using Serilog;

namespace Dalamud.Interface.Internal.Windows.StyleEditor;

/// <summary>
/// Window for the Dalamud style editor.
/// </summary>
public class StyleEditorWindow : Window
{
    private ImGuiColorEditFlags alphaFlags = ImGuiColorEditFlags.AlphaPreviewHalf;

    private int    currentSel   = 0;
    private string initialStyle = string.Empty;
    private bool   didSave      = false;
    private bool   anyChanges   = false;

    private string renameText         = string.Empty;
    private bool   renameModalDrawing = false;

    /// <summary>
    /// Initializes a new instance of the <see cref="StyleEditorWindow"/> class.
    /// </summary>
    public StyleEditorWindow()
        : base("Dalamud 样式编辑器")
    {
        this.IsOpen = true;
        this.SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = new Vector2(890, 560),
        };
    }

    /// <inheritdoc />
    public override void OnOpen()
    {
        this.didSave = false;

        var config = Service<DalamudConfiguration>.Get();
        config.SavedStyles ??= [];
        this.currentSel    =   config.SavedStyles.FindIndex(x => x.Name == config.ChosenStyle);

        this.initialStyle = config.ChosenStyle;

        base.OnOpen();
    }

    /// <inheritdoc />
    public override void OnClose()
    {
        if (!this.didSave)
        {
            var config   = Service<DalamudConfiguration>.Get();
            var newStyle = config.SavedStyles.FirstOrDefault(x => x.Name == this.initialStyle);
            newStyle?.Apply();

            if (this.anyChanges)
            {
                Service<InterfaceManager>.Get().InvokeStyleChanged();
            }
        }

        base.OnClose();
    }

    /// <inheritdoc />
    public override void Draw()
    {
        var config           = Service<DalamudConfiguration>.Get();
        var renameModalTitle = "重命名样式";

        if (currentSel >= config.SavedStyles.Count)
            currentSel = 0;

        var workStyle = config.SavedStyles[this.currentSel];
        workStyle.BuiltInColors ??= StyleModelV1.DalamudStandard.BuiltInColors.Clone();

        var isBuiltinStyle   = this.currentSel < 3;
        var appliedThisFrame = false;

        var styleAry = config.SavedStyles.Select(x => x.Name).ToArray();
        ImGui.Text("选择样式：");

        if (ImGui.Combo("###styleChooserCombo", ref this.currentSel, styleAry))
        {
            var newStyle = config.SavedStyles[this.currentSel];
            newStyle.Apply();
            this.Change();
            appliedThisFrame = true;
        }

        ImGui.SameLine();
        ImGuiHelpers.ScaledDummy(10);
        ImGui.SameLine();

        if (ImGui.Button("新建样式"))
        {
            this.SaveStyle();

            var newStyle = StyleModelV1.DalamudStandard.Clone();
            newStyle.Name = Util.GetRandomName();
            config.SavedStyles.Add(newStyle);

            this.currentSel = config.SavedStyles.Count - 1;

            newStyle.Apply();
            this.Change();
            appliedThisFrame = true;

            config.QueueSave();
        }

        ImGui.SameLine();

        if (isBuiltinStyle)
            ImGui.BeginDisabled();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Trash) && this.currentSel != 0)
        {
            var deletingStyle       = config.SavedStyles[this.currentSel];
            var deletingChosenStyle = config.ChosenStyle == deletingStyle.Name;

            // Reset assignments
            foreach (var assignment in config.CharacterStyleAssignments.Where(a => a.StyleName == deletingStyle.Name))
                assignment.StyleName = null;

            this.currentSel--;
            var newStyle = config.SavedStyles[this.currentSel];
            newStyle.Apply();
            this.Change();
            appliedThisFrame = true;

            config.SavedStyles.RemoveAt(this.currentSel + 1);

            if (deletingChosenStyle)
                config.ChosenStyle = newStyle.Name;

            config.QueueSave();
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("删除当前样式");

        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.Pen) && this.currentSel != 0)
        {
            var newStyle = config.SavedStyles[this.currentSel];
            this.renameText = newStyle.Name;

            this.renameModalDrawing = true;
            ImGui.OpenPopup(renameModalTitle);
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("重命名当前样式");

        if (isBuiltinStyle)
            ImGui.EndDisabled();

        ImGui.SameLine();

        ImGuiHelpers.ScaledDummy(5);
        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.FileExport))
        {
            var selectedStyle = config.SavedStyles[this.currentSel];
            var exportStyle   = isBuiltinStyle ? selectedStyle : StyleModelV1.Get();
            exportStyle.Name = selectedStyle.Name;
            ImGui.SetClipboardText(exportStyle.Serialize());
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("复制样式到剪贴板");

        ImGui.SameLine();

        if (ImGuiComponents.IconButton(FontAwesomeIcon.FileImport))
        {
            this.SaveStyle();

            var styleJson = ImGui.GetClipboardText();

            try
            {
                var newStyle = StyleModel.Deserialize(styleJson);

                newStyle.Name ??= Util.GetRandomName();

                if (config.SavedStyles.Any(x => x.Name == newStyle.Name))
                {
                    newStyle.Name = $"{newStyle.Name} ({Util.GetRandomName()} Mix)";
                }

                config.SavedStyles.Add(newStyle);
                newStyle.Apply();
                this.Change();
                appliedThisFrame = true;

                this.currentSel = config.SavedStyles.Count - 1;

                config.QueueSave();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Could not import style");
            }
        }

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("从剪贴板导入样式");

        ImGui.Separator();

        ImGui.PushItemWidth(ImGui.GetWindowWidth() * 0.50f);

        if (appliedThisFrame)
        {
            ImGui.Text("正在应用样式……");
        }
        else if (ImGui.BeginTabBar("StyleEditorTabs"u8))
        {
            var style   = ImGui.GetStyle();
            var changes = false;

            if (ImGui.BeginTabItem("变量"))
            {
                this.DrawBuiltinWarning(isBuiltinStyle);
                using var disabled = ImRaii.Disabled(isBuiltinStyle);

                if (ImGui.BeginChild($"ScrollingVars", ImGuiHelpers.ScaledVector2(0, 0), true, ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoBackground))
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 5);

                    changes |= ImGui.SliderFloat2("WindowPadding",     ref style.WindowPadding,     0.0f, 20.0f, "%.0f");
                    changes |= ImGui.SliderFloat2("FramePadding",      ref style.FramePadding,      0.0f, 20.0f, "%.0f");
                    changes |= ImGui.SliderFloat2("CellPadding",       ref style.CellPadding,       0.0f, 20.0f, "%.0f");
                    changes |= ImGui.SliderFloat2("ItemSpacing",       ref style.ItemSpacing,       0.0f, 20.0f, "%.0f");
                    changes |= ImGui.SliderFloat2("ItemInnerSpacing",  ref style.ItemInnerSpacing,  0.0f, 20.0f, "%.0f");
                    changes |= ImGui.SliderFloat2("TouchExtraPadding", ref style.TouchExtraPadding, 0.0f, 10.0f, "%.0f");
                    changes |= ImGui.SliderFloat("IndentSpacing"u8, ref style.IndentSpacing, 0.0f, 30.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("ScrollbarSize"u8, ref style.ScrollbarSize, 1.0f, 20.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("GrabMinSize"u8,   ref style.GrabMinSize,   1.0f, 20.0f, "%.0f"u8);
                    ImGui.Text("边框");
                    changes |= ImGui.SliderFloat("WindowBorderSize"u8, ref style.WindowBorderSize, 0.0f, 1.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("ChildBorderSize"u8,  ref style.ChildBorderSize,  0.0f, 1.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("PopupBorderSize"u8,  ref style.PopupBorderSize,  0.0f, 1.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("FrameBorderSize"u8,  ref style.FrameBorderSize,  0.0f, 1.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("TabBorderSize"u8,    ref style.TabBorderSize,    0.0f, 1.0f, "%.0f"u8);
                    ImGui.Text("圆角");
                    changes |= ImGui.SliderFloat("WindowRounding"u8,    ref style.WindowRounding,    0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("ChildRounding"u8,     ref style.ChildRounding,     0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("FrameRounding"u8,     ref style.FrameRounding,     0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("PopupRounding"u8,     ref style.PopupRounding,     0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("ScrollbarRounding"u8, ref style.ScrollbarRounding, 0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("GrabRounding"u8,      ref style.GrabRounding,      0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("LogSliderDeadzone"u8, ref style.LogSliderDeadzone, 0.0f, 12.0f, "%.0f"u8);
                    changes |= ImGui.SliderFloat("TabRounding"u8,       ref style.TabRounding,       0.0f, 12.0f, "%.0f"u8);
                    ImGui.Text("对齐");
                    changes |= ImGui.SliderFloat2("WindowTitleAlign", ref style.WindowTitleAlign, 0.0f, 1.0f, "%.2f");
                    var windowMenuButtonPosition = (int)style.WindowMenuButtonPosition + 1;

                    if (ImGui.Combo("WindowMenuButtonPosition"u8, ref windowMenuButtonPosition, ["无", "左", "右"]))
                    {
                        style.WindowMenuButtonPosition = (ImGuiDir)(windowMenuButtonPosition - 1);
                        changes                        = true;
                    }

                    changes |= ImGui.SliderFloat2("ButtonTextAlign", ref style.ButtonTextAlign, 0.0f, 1.0f, "%.2f");
                    ImGui.SameLine();
                    ImGuiComponents.HelpMarker("按钮大于其文本内容时，对齐方式才会生效。");
                    changes |= ImGui.SliderFloat2("SelectableTextAlign", ref style.SelectableTextAlign, 0.0f, 1.0f, "%.2f");
                    ImGui.SameLine();
                    ImGuiComponents.HelpMarker("下拉选择项大于其文本内容时，对齐方式才会生效。");
                    changes |= ImGui.SliderFloat2("DisplaySafeAreaPadding", ref style.DisplaySafeAreaPadding, 0.0f, 30.0f, "%.0f");
                    ImGui.SameLine();
                    ImGuiComponents.HelpMarker
                    (
                        "如果看不到屏幕边缘（例如缩放尚未配置的电视），请调整此项。"
                    );

                    ImGui.EndChild();
                }

                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("颜色"))
            {
                this.DrawBuiltinWarning(isBuiltinStyle);
                using var disabled = ImRaii.Disabled(isBuiltinStyle);

                if (ImGui.BeginChild
                        ("ScrollingColors"u8, ImGuiHelpers.ScaledVector2(0, 0), true, ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoBackground))
                {
                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() - 5);

                    if (ImGui.RadioButton("不透明", this.alphaFlags == ImGuiColorEditFlags.None))
                        this.alphaFlags = ImGuiColorEditFlags.None;
                    ImGui.SameLine();
                    if (ImGui.RadioButton("透明度", this.alphaFlags == ImGuiColorEditFlags.AlphaPreview))
                        this.alphaFlags = ImGuiColorEditFlags.AlphaPreview;
                    ImGui.SameLine();
                    if (ImGui.RadioButton("两者", this.alphaFlags == ImGuiColorEditFlags.AlphaPreviewHalf))
                        this.alphaFlags = ImGuiColorEditFlags.AlphaPreviewHalf;
                    ImGui.SameLine();

                    ImGuiComponents.HelpMarker
                    (
                        "颜色列表：\n"        +
                        "左键点击色块打开取色器，\n" +
                        "右键点击打开编辑选项菜单。"
                    );

                    foreach (var imGuiCol in Enum.GetValues<ImGuiCol>())
                    {
                        if (imGuiCol == ImGuiCol.Count)
                            continue;

                        ImGui.PushID(imGuiCol.ToString());

                        changes |= ImGui.ColorEdit4("##color", ref style.Colors[(int)imGuiCol], ImGuiColorEditFlags.AlphaBar | this.alphaFlags);

                        ImGui.SameLine(0.0f, style.ItemInnerSpacing.X);
                        ImGui.Text(imGuiCol.ToString());

                        ImGui.PopID();
                    }

                    ImGui.Separator();

                    foreach (var property in typeof(DalamudColors).GetProperties(BindingFlags.Public | BindingFlags.Instance))
                    {
                        ImGui.PushID(property.Name);

                        var colorVal = property.GetValue(workStyle.BuiltInColors);

                        if (colorVal == null)
                        {
                            colorVal = property.GetValue(StyleModelV1.DalamudStandard.BuiltInColors);
                            property.SetValue(workStyle.BuiltInColors, colorVal);
                        }

                        if (colorVal == null)
                            continue;

                        var color = (Vector4)colorVal;

                        if (ImGui.ColorEdit4("##color", ref color, ImGuiColorEditFlags.AlphaBar | this.alphaFlags))
                        {
                            property.SetValue(workStyle.BuiltInColors, color);
                            workStyle.BuiltInColors?.Apply();
                            changes = true;
                        }

                        ImGui.SameLine(0.0f, style.ItemInnerSpacing.X);
                        ImGui.Text(property.Name);

                        ImGui.PopID();
                    }

                    ImGui.EndChild();
                }

                ImGui.EndTabItem();
            }

            if (workStyle is StyleModelV1 workStyleV1 && ImGui.BeginTabItem("毛玻璃效果"))
            {
                this.DrawBuiltinWarning(isBuiltinStyle);
                using var disabledBlur = ImRaii.Disabled(isBuiltinStyle);
                ImGui.TextWrapped("背景毛玻璃效果强度");

                var v = workStyleV1.WindowBlurStrength * 100f;

                if (ImGui.SliderFloat($"###blurStrength", ref v, 0f, 100f, "%.1f%%"))
                {
                    workStyleV1.WindowBlurStrength             = v / 100f;
                    WindowSystem.DefaultBackgroundBlurStrength = workStyleV1.WindowBlurStrength;
                    changes                                    = true;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.DalamudGrey);
                ImGui.TextWrapped
                (
                    "设置插件窗口背景毛玻璃效果的强度。\n" +
                    "设为 0% 可关闭毛玻璃效果。并非所有插件都支持该效果，如需插件支持，请联系插件作者。"
                );
                ImGui.PopStyleColor();

                ImGuiHelpers.ScaledDummy(5);

                ImGui.TextWrapped("背景毛玻璃效果色调");
                var tint = workStyleV1.WindowBlurTint;

                if (ImGui.ColorEdit4
                    (
                        $"###blurTint",
                        ref tint,
                        ImGuiColorEditFlags.AlphaBar | ImGuiColorEditFlags.AlphaPreviewHalf
                    ))
                {
                    workStyleV1.WindowBlurTint             = tint;
                    WindowSystem.DefaultBackgroundBlurTint = workStyleV1.WindowBlurTint;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.DalamudGrey);
                ImGui.TextWrapped
                (
                    "为未聚焦状态下的窗口叠加背景毛玻璃色调。"
                );
                ImGui.PopStyleColor();

                ImGuiHelpers.ScaledDummy(5);

                ImGui.TextWrapped("背景毛玻璃效果色调（窗口聚焦状态下）");
                var tintActive = workStyleV1.WindowBlurTintActive;

                if (ImGui.ColorEdit4
                    (
                        $"###blurTintActive",
                        ref tintActive,
                        ImGuiColorEditFlags.AlphaBar | ImGuiColorEditFlags.AlphaPreviewHalf
                    ))
                {
                    workStyleV1.WindowBlurTintActive             = tintActive;
                    WindowSystem.DefaultBackgroundBlurTintActive = workStyleV1.WindowBlurTintActive;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.DalamudGrey);
                ImGui.TextWrapped
                (
                    "为聚焦状态下的窗口叠加背景毛玻璃色调。"
                );
                ImGui.PopStyleColor();

                ImGuiHelpers.ScaledDummy(5);

                ImGui.TextWrapped("背景毛玻璃效果明度");
                var luminosity = workStyleV1.WindowBlurLuminosity;

                if (ImGui.ColorEdit4
                    (
                        $"###blurLuminosity",
                        ref luminosity,
                        ImGuiColorEditFlags.AlphaBar | ImGuiColorEditFlags.AlphaPreviewHalf
                    ))
                {
                    workStyleV1.WindowBlurLuminosity             = luminosity;
                    WindowSystem.DefaultBackgroundBlurLuminosity = workStyleV1.WindowBlurLuminosity;
                }

                ImGui.PushStyleColor(ImGuiCol.Text, ImGuiColors.DalamudGrey);
                ImGui.TextWrapped
                (
                    "明度目标颜色（RGB）与明度混合强度（Alpha）。\n" +
                    "用目标颜色的明度替换毛玻璃背景的明度，以此降低毛玻璃背景的对比度，同时保留其色相与饱和度。"
                );
                ImGui.PopStyleColor();

                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("角色分配"))
            {
                this.DrawCharacterAssignmentsTab(config);
                ImGui.EndTabItem();
            }

            if (changes)
            {
                this.Change();
            }

            ImGui.EndTabBar();
        }

        ImGui.PopItemWidth();

        if (DalamudComponents.DrawFloatingSaveDiscardButtons(out var saveClicked))
            this.IsOpen = false;

        if (saveClicked)
        {
            this.SaveStyle();

            config.ChosenStyle = config.SavedStyles[this.currentSel].Name;
            Log.Verbose("ChosenStyle = {ChosenStyle}", config.ChosenStyle);

            this.didSave = true;
        }

        if (ImGui.BeginPopupModal(renameModalTitle, ref this.renameModalDrawing, ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar))
        {
            ImGui.Text("请输入该样式的新名称。");
            ImGui.Spacing();

            ImGui.InputText("###renameModalInput"u8, ref this.renameText, 255);

            const float buttonWidth = 120f;
            ImGui.SetCursorPosX((ImGui.GetWindowWidth() - buttonWidth) / 2);

            if (ImGui.Button("确定", new Vector2(buttonWidth, 40)))
            {
                config.SavedStyles[this.currentSel].Name = this.renameText;
                config.QueueSave();

                ImGui.CloseCurrentPopup();
            }

            ImGui.EndPopup();
        }
    }

    private void DrawBuiltinWarning
    (
        bool isBuiltinStyle
    )
    {
        if (!isBuiltinStyle)
            return;

        ImGui.TextColored(ImGuiColors.AttentionForeground, "无法编辑内置样式，请先新建一个样式。");
        ImGuiHelpers.ScaledDummy(3);
    }

    private void DrawCharacterAssignmentsTab
    (
        DalamudConfiguration config
    )
    {
        ImGui.TextWrapped
        (
            "为每个角色指定样式。该角色登录时会自动应用指定的样式。"
        );
        ImGuiHelpers.ScaledDummy(5);

        var styleNames = config.SavedStyles?.Select(x => x.Name).ToArray() ?? [];

        var comboItems = new string[styleNames.Length + 1];
        comboItems[0] = "最后选择的样式";
        for (var i = 0; i < styleNames.Length; i++)
            comboItems[i + 1] = styleNames[i];

        ulong? wantRemoveContentId = null;

        var comboWidth = ImGuiHelpers.GlobalScale * 300;

        using var child = ImRaii.Child("###characterAssignmentsScroll"u8);

        if (child)
        {
            if (config.CharacterStyleAssignments.Count == 0)
            {
                ImGui.TextColored
                (
                    ImGuiColors.DalamudGrey,
                    "尚未分配任何角色。使用下方按钮添加当前角色。"
                );
            }
            else if (ImGui.BeginTable
                     (
                         "###charStyleTable",
                         3,
                         ImGuiTableFlags.RowBg | ImGuiTableFlags.SizingFixedFit | ImGuiTableFlags.BordersInnerV
                     ))
            {
                ImGui.TableSetupColumn("###remove"u8,   ImGuiTableColumnFlags.WidthFixed);
                ImGui.TableSetupColumn("###charname"u8, ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("###style"u8,    ImGuiTableColumnFlags.WidthFixed, comboWidth);

                foreach (var entry in config.CharacterStyleAssignments.ToArray())
                {
                    ImGui.TableNextRow();

                    ImGui.TableSetColumnIndex(0);
                    if (ImGuiComponents.IconButton($"###removeCharStyle{entry.ContentId}", FontAwesomeIcon.Trash))
                        wantRemoveContentId = entry.ContentId;

                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("移除该角色分配");

                    ImGui.TableSetColumnIndex(1);
                    string characterDisplay;
                    if (!string.IsNullOrEmpty(entry.DisplayName) && !string.IsNullOrEmpty(entry.ServerName))
                        characterDisplay = $"{entry.DisplayName} <icon({(int)BitmapFontIcon.CrossWorld})> {entry.ServerName}";
                    else
                        characterDisplay = entry.ContentId.ToString();

                    ImGui.SetCursorPosY(ImGui.GetCursorPosY() + (ImGui.GetFrameHeight() / 2f) - (ImGui.GetTextLineHeight() / 2f));
                    ImGuiHelpers.CompileSeStringWrapped(characterDisplay);

                    ImGui.TableSetColumnIndex(2);
                    var currentStyleIdx = string.IsNullOrEmpty(entry.StyleName) || !styleNames.Contains(entry.StyleName)
                                              ? 0
                                              : Array.IndexOf(styleNames, entry.StyleName) + 1;
                    if (currentStyleIdx < 0) currentStyleIdx = 0;

                    ImGui.SetNextItemWidth(comboWidth);

                    if (ImGui.Combo($"###styleCombo{entry.ContentId}", ref currentStyleIdx, comboItems, comboItems.Length))
                    {
                        entry.StyleName = currentStyleIdx == 0 ? null : styleNames[currentStyleIdx - 1];
                        config.QueueSave();
                    }
                }

                ImGui.EndTable();
            }
        }

        if (wantRemoveContentId != null)
        {
            var toRemove = config.CharacterStyleAssignments.FirstOrDefault(x => x.ContentId == wantRemoveContentId.Value);

            if (toRemove != null)
            {
                config.CharacterStyleAssignments.Remove(toRemove);
                config.QueueSave();
            }
        }

        ImGuiHelpers.ScaledDummy(5);
        ImGui.Separator();
        ImGuiHelpers.ScaledDummy(5);

        var player = Service<PlayerState>.Get();

        if (player.IsLoaded)
        {
            using var disabled = ImRaii.Disabled(config.CharacterStyleAssignments.Any(x => x.ContentId == player.ContentId));

            if (ImGuiComponents.IconButtonWithText
                (
                    FontAwesomeIcon.Plus,
                    string.Format
                    (
                        "添加当前角色：{0}",
                        player.CharacterName
                    )
                ))
            {
                var serverName = player.HomeWorld.Value.Name.ExtractText();
                config.CharacterStyleAssignments.Add(new CharacterStyleAssignment(player.CharacterName, player.ContentId, serverName));
                config.QueueSave();
            }
        }
        else
        {
            ImGui.TextColored
            (
                ImGuiColors.DalamudGrey,
                "需要登录游戏才能添加当前角色。"
            );
        }
    }

    private void SaveStyle()
    {
        if (this.currentSel < 3)
            return;

        var config = Service<DalamudConfiguration>.Get();

        var newStyle = StyleModelV1.Get();
        newStyle.Name                       = config.SavedStyles[this.currentSel].Name;
        config.SavedStyles[this.currentSel] = newStyle;
        newStyle.Apply();

        config.QueueSave();
    }

    private void Change()
    {
        this.anyChanges = true;
        Service<InterfaceManager>.Get().InvokeStyleChanged();
    }
}
