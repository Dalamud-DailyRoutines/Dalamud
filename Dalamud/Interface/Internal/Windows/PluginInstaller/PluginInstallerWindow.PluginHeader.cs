using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Interface.Animation.EasingFunctions;
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
    private readonly Stopwatch tooltipFadeInStopwatch = new();

    private readonly InOutCubic tooltipFadeEasing = new(TimeSpan.FromSeconds(0.2f))
    {
        Point1 = Vector2.Zero,
        Point2 = Vector2.One
    };

    private string currentlyHoveredPlugin = string.Empty;

    private string currentlyHoveredObject = string.Empty;

    [Flags]
    private enum PluginHeaderFlags
    {
        None                  = 0,
        IsThirdParty          = 1 << 0,
        HasTrouble            = 1 << 1,
        UpdateAvailable       = 1 << 2,
        MainRepoCrossUpdate   = 1 << 3,
        IsNew                 = 1 << 4,
        IsInstallableOutdated = 1 << 5,
        IsOrphan              = 1 << 6,
        IsTesting             = 1 << 7,
        IsIncompatible        = 1 << 8
    }

    private bool DrawPluginCollapsingHeader
    (
        string            label,
        LocalPlugin?      plugin,
        IPluginManifest   manifest,
        PluginHeaderFlags flags,
        Action            drawContextMenuAction,
        int               index
    )
    {
        var pluginKey = plugin != null ?
                            $"installed:{plugin.EffectiveWorkingPluginId}" :
                            $"{((RemotePluginManifest)manifest).SourceRepo.PluginMasterUrl}:{manifest.InternalName}";
        var isOpen = this.openPluginCollapsibles.Contains(pluginKey);

        var sectionSize = ImGuiHelpers.GlobalScale * 66;

        ImGui.Separator();

        var                    childId     = $"plugin_child_{label}_{plugin?.EffectiveWorkingPluginId}_{manifest.InternalName}";
        const ImGuiWindowFlags CHILD_FLAGS = ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse;

        using var pluginChild = ImRaii.Child(childId, new Vector2(ImGui.GetContentRegionAvail().X, sectionSize), false, CHILD_FLAGS);

        if (!pluginChild)
        {
            return isOpen;
        }

        var startCursor = ImGui.GetCursorPos();

        if (flags.HasFlag(PluginHeaderFlags.IsTesting))
        {
            void DrawCautionTape
            (
                Vector2 position,
                Vector2 size,
                float   stripeWidth,
                float   skewAmount
            )
            {
                var wdl = ImGui.GetWindowDrawList();

                var windowPos = ImGui.GetWindowPos();
                var scroll    = new Vector2(ImGui.GetScrollX(), ImGui.GetScrollY());

                var adjustedPosition = windowPos + position - scroll;

                var yellow     = ImGui.ColorConvertFloat4ToU32(new Vector4(1.0f, 0.9f, 0.0f, 0.10f));
                var numStripes = (int)(size.X / stripeWidth) + (int)(size.Y / skewAmount) + 1; // +1 to cover partial stripe

                for (var i = 0; i < numStripes; i++)
                {
                    var x0 = adjustedPosition.X + (i * stripeWidth);
                    var x1 = x0                 + stripeWidth;
                    var y0 = adjustedPosition.Y;
                    var y1 = y0 + size.Y;

                    var p0 = new Vector2(x0,              y0);
                    var p1 = new Vector2(x1,              y0);
                    var p2 = new Vector2(x1 - skewAmount, y1);
                    var p3 = new Vector2(x0 - skewAmount, y1);

                    if (i % 2 != 0)
                        continue;

                    wdl.AddQuadFilled(p0, p1, p2, p3, yellow);
                }
            }

            DrawCautionTape
            (
                startCursor + new Vector2(0, 1),
                new Vector2(ImGui.GetWindowWidth(), sectionSize + ImGui.GetStyle().ItemSpacing.Y),
                ImGuiHelpers.GlobalScale * 40,
                20
            );
        }

        ImGui.PushStyleColor
        (
            ImGuiCol.Button,
            isOpen ?
                new Vector4(0.5f, 0.5f, 0.5f, 0.1f) :
                Vector4.Zero
        );

        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.5f, 0.5f, 0.5f, 0.2f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  new Vector4(0.5f, 0.5f, 0.5f, 0.35f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 0);

        ImGui.SetCursorPos(startCursor);

        if (ImGui.Button($"###plugin{index}CollapsibleBtn", new Vector2(ImGui.GetContentRegionAvail().X, sectionSize + ImGui.GetStyle().ItemSpacing.Y)))
        {
            if (isOpen)
            {
                this.openPluginCollapsibles.Remove(pluginKey);
            }
            else
            {
                this.openPluginCollapsibles.Add(pluginKey);
            }

            isOpen = !isOpen;
        }

        drawContextMenuAction?.Invoke();

        ImGui.PopStyleVar();

        ImGui.PopStyleColor(3);

        ImGui.SetCursorPos(startCursor);

        var pluginDisabled = plugin is { IsWantedByAnyProfile: false };

        var iconSize          = ImGuiHelpers.ScaledVector2(64, 64);
        var cursorBeforeImage = ImGui.GetCursorPos();
        var rectOffset        = ImGui.GetWindowContentRegionMin() + ImGui.GetWindowPos();

        var overlayAlpha = 1.0f;

        if (ImGui.IsRectVisible(rectOffset + cursorBeforeImage, rectOffset + cursorBeforeImage + iconSize))
        {
            var iconTex = this.imageCache.DefaultIcon;
            var hasIcon = this.imageCache.TryGetIcon(plugin, manifest, flags.HasFlag(PluginHeaderFlags.IsThirdParty), out var cachedIconTex, out var loadedSince);

            if (hasIcon && cachedIconTex != null)
            {
                iconTex = cachedIconTex;
            }

            const float FADE_TIME = 0.3f;
            var         iconAlpha = 1f;

            if (loadedSince.HasValue)
            {
                float EaseOutCubic
                (
                    float t
                ) => 1 - MathF.Pow(1 - t, 3);

                var secondsSinceLoad = (float)DateTime.Now.Subtract(loadedSince.Value).TotalSeconds;
                var fadeTo = pluginDisabled || flags.HasFlag(PluginHeaderFlags.IsInstallableOutdated) ?
                                 0.4f :
                                 1f;

                float Interp
                (
                    float to
                ) => Math.Clamp(EaseOutCubic(Math.Min(secondsSinceLoad, FADE_TIME) / FADE_TIME) * to, 0, 1);

                iconAlpha    = Interp(fadeTo);
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
        else if ((flags.HasFlag(PluginHeaderFlags.HasTrouble) && !pluginDisabled) ||
                 flags.HasFlag(PluginHeaderFlags.IsOrphan)                        ||
                 flags.HasFlag(PluginHeaderFlags.IsIncompatible))
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

            var verifiedOutlineColor   = KnownColor.White.Vector() with { W = 0.75f };
            var unverifiedOutlineColor = KnownColor.Black.Vector();
            var verifiedIconColor      = KnownColor.RoyalBlue.Vector() with { W = 0.75f };
            var unverifiedIconColor    = KnownColor.Orange.Vector();
            var devIconOutlineColor    = KnownColor.White.Vector();
            var devIconColor           = KnownColor.MediumOrchid.Vector();

            const string TOOLTIP_IDENTIFIER = "VerifiedCheckmarkIcon";

            if (plugin is LocalDevPlugin)
            {
                DrawFontawesomeIconOutlined(FontAwesomeIcon.Wrench, devIconOutlineColor, devIconColor);
                this.IconFadeTooltip(label, TOOLTIP_IDENTIFIER, "这是手动添加的开发版插件。");
            }
            else if (!flags.HasFlag(PluginHeaderFlags.IsThirdParty))
            {
                DrawFontawesomeIconOutlined(FontAwesomeIcon.CheckCircle, verifiedOutlineColor, verifiedIconColor);
                this.IconFadeTooltip(label, TOOLTIP_IDENTIFIER, "已验证");
            }
            else
            {
                DrawFontawesomeIconOutlined(FontAwesomeIcon.ExclamationCircle, unverifiedOutlineColor, unverifiedIconColor);
                this.IconFadeTooltip(label, TOOLTIP_IDENTIFIER, "未验证");
            }
        }

        // Pinned indicator
        if (plugin != null && Service<DalamudConfiguration>.Get().PinnedPluginInternalName.Contains(plugin.Manifest.InternalName))
        {
            ImGui.SameLine();
            ImGui.Text(" "u8);
            ImGui.SameLine();

            var pinIconOutlineColor = KnownColor.Crimson.Vector();
            var pinIconColor        = KnownColor.White.Vector() with { W = 0.75f };

            const string TOOLTIP_IDENTIFIER = "PinnedIcon";

            DrawFontawesomeIconOutlined(FontAwesomeIcon.Thumbtack, pinIconOutlineColor, pinIconColor);
            this.IconFadeTooltip(label, TOOLTIP_IDENTIFIER, "已置顶");
        }

        // Favorite star indicator
        if (plugin != null && Service<DalamudConfiguration>.Get().FavoritePluginInternalName.Contains(plugin.Manifest.InternalName))
        {
            ImGui.SameLine();
            ImGui.Text(" "u8);
            ImGui.SameLine();

            var starIconOutlineColor = KnownColor.Black.Vector();
            var starIconColor        = KnownColor.Gold.Vector();

            const string TOOLTIP_IDENTIFIER = "FavoriteIcon";

            DrawFontawesomeIconOutlined(FontAwesomeIcon.Star, starIconOutlineColor, starIconColor);
            this.IconFadeTooltip(label, TOOLTIP_IDENTIFIER, "已收藏");
        }

        // Download count
        var downloadCountText = manifest.DownloadCount > 0 ?
                                    $" 作者：{manifest.Author}（{manifest.DownloadCount:N0} 次下载）" :
                                    $" 作者：{manifest.Author}";

        if (plugin is LocalDevPlugin devPlugin && !devPlugin.Nickname.IsNullOrWhitespace())
        {
            downloadCountText += $"（{devPlugin.Nickname}）";
        }

        ImGui.SameLine();
        ImGui.TextColored(ImGuiColors.DalamudGrey3, downloadCountText);

        if (flags.HasFlag(PluginHeaderFlags.IsNew))
        {
            ImGui.SameLine();
            ImGui.TextColored(ImGuiColors.TankBlue, " 新插件");
        }

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        if (plugin is { State: PluginState.LoadError or PluginState.UnloadError or PluginState.DependencyResolutionFailed })
        {
            if (ImGui.SmallButton("查看日志"))
                Service<DalamudInterface>.Get().OpenLogWindow();
            ImGui.SameLine();
        }

        // Outdated warning
        if (flags.HasFlag(PluginHeaderFlags.IsIncompatible))
        {
            using var color = ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
            ImGui.TextWrapped("此插件与当前 Dalamud 版本不兼容，请尝试重启游戏");
        }
        else if (plugin is { IsOutdated: true, IsBanned: false } || flags.HasFlag(PluginHeaderFlags.IsInstallableOutdated))
        {
            using var color = ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);

            var bodyText = $"插件 API 版本（{plugin?.Manifest.DalamudApiLevel ?? 0}）与 Dalamud API 版本（{PluginManager.DalamudApiLevel}）不匹配，无法加载。" + " ";
            if (flags.HasFlag(PluginHeaderFlags.UpdateAvailable))
                bodyText += "请更新后重试。";
            else
                bodyText += "请等待插件更新适配。";

            using (ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.DalamudRed))
                ImGui.TextWrapped(bodyText);
        }
        else
        {
            var warning = plugin switch
            {
                { IsBanned: true } =>
                    $"{(plugin.BanReason.IsNullOrEmpty() ? "此插件因不兼容而被自动禁用，目前不可用。" : $"此插件已被自动禁用：{plugin.BanReason}。")}\n{(flags.HasFlag(PluginHeaderFlags.UpdateAvailable) ? "有可用更新可安装。" : "请等待作者更新。")}",
                { IsOrphaned: true }                                                                                     => "此插件的源仓库不再可用，请尝试重新添加仓库或从其他仓库安装。",
                { IsDecommissioned: true, IsThirdParty: false }                                                          => "此插件已停止维护，可以继续使用，但不会再更新，也无法重新安装。",
                { IsDecommissioned: true, IsThirdParty: true } when flags.HasFlag(PluginHeaderFlags.MainRepoCrossUpdate) => "此插件的原仓库已停止维护，可更新为官方仓库提供的版本。",
                { IsDecommissioned: true, IsThirdParty: true }                                                           => "此插件的原仓库已停止维护，可尝试从其他仓库获取更新。",
                not null when !plugin.CheckPolicy()                                                                      => "此类型的插件已被手动禁止加载。",
                { State: PluginState.LoadError or PluginState.DependencyResolutionFailed }                               => "此插件加载失败，请查看日志。",
                { State: PluginState.UnloadError }                                                                       => "此插件卸载失败，请查看日志。",
                _                                                                                                        => null
            };

            if (warning != null)
            {
                using var color = ImRaii.PushColor(ImGuiCol.Text, ImGuiColors.ErrorForeground);
                ImGui.TextWrapped(warning);
            }
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
                const int PUNCHLINE_LEN = 200;
                var       firstLine     = manifest.Description.Split('\r', '\n')[0];

                ImGui.TextWrapped
                (
                    firstLine.Length < PUNCHLINE_LEN ?
                        firstLine :
                        firstLine[..PUNCHLINE_LEN]
                );
            }
        }

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);

        return isOpen;
    }

    private static void DrawFontawesomeIconOutlined
    (
        FontAwesomeIcon icon,
        Vector4         outline,
        Vector4         iconColor
    )
    {
        var positionOffset = ImGuiHelpers.ScaledVector2(0.0f, 1.0f);
        var cursorStart    = ImGui.GetCursorPos() + positionOffset;
        ImGui.PushFont(InterfaceManager.IconFont);

        ImGui.PushStyleColor(ImGuiCol.Text, outline);

        foreach (var x in Enumerable.Range(-1, 3))
        {
            foreach (var y in Enumerable.Range(-1, 3))
            {
                if (x is 0 &&
                    y is 0)
                    continue;

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
    private void IconFadeTooltip
    (
        string plugin,
        string identifier,
        string tooltip
    )
    {
        const float FADE_IN_START_DELAY = 250.0f;

        var isHoveringSameItem = this.currentlyHoveredPlugin == plugin && this.currentlyHoveredObject == identifier;

        // If we just started a hover, start the timer
        if (ImGui.IsItemHovered() && !this.tooltipFadeInStopwatch.IsRunning)
        {
            this.currentlyHoveredPlugin = plugin;
            this.currentlyHoveredObject = identifier;
            this.tooltipFadeInStopwatch.Restart();
        }

        // If we were last hovering this plugins item and are no longer hovered over that item, reset the timer
        if (!ImGui.IsItemHovered() && isHoveringSameItem)
        {
            this.currentlyHoveredPlugin = string.Empty;
            this.currentlyHoveredObject = string.Empty;
            this.tooltipFadeInStopwatch.Stop();
            this.tooltipFadeEasing.Reset();
        }

        // If we have been hovering this item for > fadeInStartDelay milliseconds, fade in tooltip over fadeInTime milliseconds
        if (ImGui.IsItemHovered() && isHoveringSameItem && this.tooltipFadeInStopwatch.ElapsedMilliseconds >= FADE_IN_START_DELAY)
        {
            if (!this.tooltipFadeEasing.IsRunning)
                this.tooltipFadeEasing.Start();

            this.tooltipFadeEasing.Update();
            var fadePercent = this.tooltipFadeEasing.EasedPoint.X;
            ImGui.PushStyleColor(ImGuiCol.Text,    ImGui.GetStyle().Colors[(int)ImGuiCol.Text] with { W = fadePercent });
            ImGui.PushStyleColor(ImGuiCol.FrameBg, ImGui.GetStyle().Colors[(int)ImGuiCol.FrameBg] with { W = fadePercent });
            ImGui.SetTooltip(tooltip);
            ImGui.PopStyleColor(2);
        }
    }
}
