using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Textures.TextureWraps;
using Dalamud.Interface.Utility;
using Dalamud.Utility;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件安装器。
/// </summary>
internal partial class PluginInstallerWindow
{
    private readonly Vector4 changelogBgColor = new(0.114f, 0.584f, 0.192f, 0.678f);

    private readonly Vector4 changelogTextColor = new(0.812f, 1.000f, 0.816f, 1.000f);

    private DalamudChangelogManager? dalamudChangelogManager;

    private Task? dalamudChangelogRefreshTask;

    private CancellationTokenSource? dalamudChangelogRefreshTaskCts;

    private void DrawChangelogList
    (
        bool displayDalamud,
        bool displayPlugins
    )
    {
        if (!displayDalamud && this.pluginListInstalled.Count == 0)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, "当前没有安装任何插件，可从“所有插件”标签页安装");
            return;
        }

        if (this.dalamudChangelogRefreshTask?.IsFaulted  == true ||
            this.dalamudChangelogRefreshTask?.IsCanceled == true)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, "无法下载更新日志");
            if (ImGui.SmallButton("查看日志"))
                Service<DalamudInterface>.Get().OpenLogWindow();
            return;
        }

        if (this.dalamudChangelogManager?.Changelogs == null)
        {
            ImGui.TextColored(ImGuiColors.DalamudGrey, "正在加载插件……");

            if (this.dalamudChangelogManager     != null &&
                this.dalamudChangelogRefreshTask == null)
            {
                this.dalamudChangelogRefreshTaskCts = new CancellationTokenSource();
                this.dalamudChangelogRefreshTask    = Task.Run(this.dalamudChangelogManager.ReloadChangelogAsync, this.dalamudChangelogRefreshTaskCts.Token);
                _ = this.dalamudChangelogRefreshTask.ContinueWith
                (t =>
                    {
                        if (!t.IsCompletedSuccessfully)
                        {
                            Log.Error(t.Exception, "Failed to load changelogs");
                        }
                    }
                );
            }

            return;
        }

        IEnumerable<IChangelogEntry>? changelogs = (displayDalamud, displayPlugins) switch
        {
            (true, true)  => this.dalamudChangelogManager.Changelogs,
            (true, false) => this.dalamudChangelogManager.Changelogs?.OfType<DalamudChangelogEntry>(),
            (false, true) => this.dalamudChangelogManager.Changelogs?.OfType<PluginChangelogEntry>(),
            _             => null
        };
        var entries   = new List<IChangelogEntry>();
        var hasSearch = !string.IsNullOrWhiteSpace(this.searchText);
        var matcher   = new FuzzyMatcher(this.searchText.ToLowerInvariant(), MatchMode.FuzzyParts);

        if (changelogs != null)
        {
            foreach (var entry in changelogs)
            {
                if (!hasSearch ||
                    matcher.Matches(entry.Title.ToLowerInvariant()) > 0)
                    entries.Add(entry);
            }
        }

        var sortedChangelogs = entries.OrderByDescending(entry => entry.Date).ToList();

        if (sortedChangelogs.Count == 0)
        {
            ImGui.TextColored
            (
                ImGuiColors.DalamudGrey2,
                this.pluginListInstalled.Any(plugin => !plugin.Manifest.Changelog.IsNullOrEmpty()) ?
                    "未找到符合搜索条件的插件" :
                    "已安装的插件均无更新日志"
            );

            return;
        }

        foreach (var logEntry in sortedChangelogs)
        {
            this.DrawChangelog(logEntry);
        }
    }

    private void DrawChangelog
    (
        IChangelogEntry log
    )
    {
        ImGui.Separator();

        var startCursor = ImGui.GetCursorPos();

        var iconSize          = ImGuiHelpers.ScaledVector2(64, 64);
        var cursorBeforeImage = ImGui.GetCursorPos();
        var rectOffset        = ImGui.GetWindowContentRegionMin() + ImGui.GetWindowPos();

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
            ImGui.TextColored(ImGuiColors.DalamudGrey3, $" 作者：{log.Author}");
        }

        if (log.Date != DateTime.MinValue)
        {
            var whenText = log.Date.LocRelativePastLong();
            var whenSize = ImGui.CalcTextSize(whenText);
            ImGui.SameLine(ImGui.GetWindowWidth() - whenSize.X - (25 * ImGuiHelpers.GlobalScale));
            ImGui.TextColored(ImGuiColors.DalamudGrey3, whenText);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("发布于：" + log.Date.LocAbsolute());
        }

        cursor.Y += ImGui.GetTextLineHeightWithSpacing();
        ImGui.SetCursorPos(cursor);

        ImGui.TextWrapped(log.Text);

        var endCursor = ImGui.GetCursorPos();

        var sectionSize = Math.Max
        (
            66 * ImGuiHelpers.GlobalScale, // min size due to icons
            endCursor.Y - startCursor.Y
        );

        startCursor.Y += sectionSize;
        ImGui.SetCursorPos(startCursor);
    }
}
