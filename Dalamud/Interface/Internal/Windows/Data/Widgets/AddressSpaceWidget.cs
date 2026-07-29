using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;

using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Utility.Raii;

using Serilog;

using TerraFX.Interop.Windows;

using static TerraFX.Interop.Windows.Windows;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for inspecting how much of the address space around a given address is still usable for hook trampolines.
/// </summary>
internal unsafe class AddressSpaceWidget : IDataWindowWidget
{
    // dwAllocationGranularity is always 64k for Windows on x64
    private const ulong Granularity = 0x10000;

    // rel32 displacement reach
    private const ulong RelativeJumpReach = int.MaxValue;

    private readonly List<Region> regions = [];
    private readonly List<AnchorChoice> anchors = [];

    private int selectedAnchor;
    private string customAddress = string.Empty;
    private WindowStats stats;
    private bool scanned;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["addressspace", "vmmap"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "地址空间";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
        this.scanned = false;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        if (!this.scanned)
            this.Rescan();

        if (ImGui.Button("重新扫描"u8))
            this.Rescan();

        ImGui.SameLine();
        if (ImGui.Button("将内存映射输出到日志"u8))
            this.DumpToLog();

        ImGui.SameLine();
        ImGui.TextDisabled($"{this.regions.Count} 个区域");

        ImGui.Separator();

        this.DrawAnchorPicker();

        ImGui.Separator();

        this.DrawSummary();

        ImGui.Separator();

        this.DrawFreeBlocks();
    }

    private static string FormatBytes(ulong bytes) => bytes switch
    {
        >= 1UL << 30 => $"{bytes / (double)(1UL << 30):F2} GB",
        >= 1UL << 20 => $"{bytes / (double)(1UL << 20):F2} MB",
        >= 1UL << 10 => $"{bytes / (double)(1UL << 10):F2} KB",
        _ => $"{bytes} B",
    };

    private static (ulong Count, ulong First) CountGranules(ulong start, ulong end)
    {
        if (end <= start || end - start < Granularity)
            return (0, 0);

        var first = (start + Granularity - 1) & ~(Granularity - 1);
        var last = (end - Granularity) & ~(Granularity - 1);

        if (last < first)
            return (0, 0);

        return (((last - first) / Granularity) + 1, first);
    }

    private void Rescan()
    {
        this.scanned = true;
        this.regions.Clear();

        MEMORY_BASIC_INFORMATION mbi;
        ulong address = 0;

        while (VirtualQuery((void*)address, &mbi, (nuint)sizeof(MEMORY_BASIC_INFORMATION)) != 0)
        {
            var start = (ulong)mbi.BaseAddress;
            var size = (ulong)mbi.RegionSize;

            if (size == 0)
                break;

            this.regions.Add(new Region(start, size, mbi.State, mbi.Protect));

            var next = start + size;
            if (next <= address)
                break;

            address = next;
        }

        this.RefreshAnchors();
        this.Recompute();
    }

    private void RefreshAnchors()
    {
        this.anchors.Clear();

        try
        {
            using var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                var mid = (ulong)module.BaseAddress + ((ulong)module.ModuleMemorySize / 2);
                this.anchors.Add(new AnchorChoice($"{module.ModuleName} (中点)", mid));
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "无法枚举地址空间工具所需的模块");
        }

        var mainName = Process.GetCurrentProcess().MainModule?.ModuleName;
        if (mainName is not null)
        {
            var index = this.anchors.FindIndex(x => x.Name.StartsWith(mainName, StringComparison.OrdinalIgnoreCase));
            if (index > 0)
            {
                var main = this.anchors[index];
                this.anchors.RemoveAt(index);
                this.anchors.Insert(0, main);
            }
        }

        this.anchors.Add(new AnchorChoice("自定义地址", 0));

        if (this.selectedAnchor >= this.anchors.Count)
            this.selectedAnchor = 0;
    }

    private ulong GetAnchorAddress()
    {
        if (this.anchors.Count == 0)
            return 0;

        var choice = this.anchors[Math.Clamp(this.selectedAnchor, 0, this.anchors.Count - 1)];
        if (choice.Name != "自定义地址")
            return choice.Address;

        var text = this.customAddress.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        return ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;
    }

    private void Recompute()
    {
        var anchor = this.GetAnchorAddress();
        if (anchor == 0)
        {
            this.stats = default;
            return;
        }

        var windowStart = anchor > RelativeJumpReach ? anchor - RelativeJumpReach : 0;
        var windowEnd = anchor + RelativeJumpReach;

        var result = new WindowStats
        {
            Anchor = anchor,
            WindowStart = windowStart,
            WindowEnd = windowEnd,
        };

        foreach (var region in this.regions)
        {
            var start = Math.Max(region.Start, windowStart);
            var end = Math.Min(region.End, windowEnd);

            if (end <= start)
                continue;

            var length = end - start;

            if ((region.State & MEM.MEM_FREE) != 0)
            {
                result.Free += length;

                var (count, _) = CountGranules(start, end);
                result.AllocatableGranules += count;

                if (count * Granularity > result.LargestFreeRun)
                    result.LargestFreeRun = count * Granularity;
            }
            else if ((region.State & MEM.MEM_COMMIT) != 0)
            {
                result.Committed += length;
            }
            else
            {
                result.Reserved += length;
            }
        }

        result.WindowSize = windowEnd - windowStart;
        this.stats = result;
    }

    private void DrawAnchorPicker()
    {
        if (this.anchors.Count == 0)
            return;

        var current = this.anchors[Math.Clamp(this.selectedAnchor, 0, this.anchors.Count - 1)];

        using (var combo = ImRaii.Combo("锚点"u8, current.Name))
        {
            if (combo.Success)
            {
                for (var i = 0; i < this.anchors.Count; i++)
                {
                    if (!ImGui.Selectable(this.anchors[i].Name, i == this.selectedAnchor))
                        continue;

                    this.selectedAnchor = i;
                    this.Recompute();
                }
            }
        }

        if (current.Name == "自定义地址" && ImGui.InputText("地址（十六进制）"u8, ref this.customAddress, 32))
            this.Recompute();
    }

    private void DrawSummary()
    {
        if (this.stats.WindowSize == 0)
        {
            ImGui.TextDisabled("选择锚点，或输入有效的十六进制地址"u8);
            return;
        }

        var s = this.stats;
        var allocatable = s.AllocatableGranules * Granularity;
        var stranded = s.Free > allocatable ? s.Free - allocatable : 0;
        var exhaustion = 1.0f - (allocatable / (float)s.WindowSize);

        ImGui.Text($"锚点 0x{s.Anchor:X}，窗口 0x{s.WindowStart:X} - 0x{s.WindowEnd:X}（{FormatBytes(s.WindowSize)}）");

        ImGui.ProgressBar(exhaustion, new Vector2(-1, 0), $"已耗尽 {exhaustion * 100:F2}%");

        using (var table = ImRaii.Table("##addressSpaceSummary"u8, 2, ImGuiTableFlags.SizingFixedFit))
        {
            if (table.Success)
            {
                Row("可分配", $"{FormatBytes(allocatable)}, 共 {s.AllocatableGranules} 个 64 KB 粒度块");
                Row("最大连续空间", FormatBytes(s.LargestFreeRun));
                Row("空闲 (原始)", FormatBytes(s.Free));
                Row("零散空闲空间", FormatBytes(stranded));
                Row("已保留", FormatBytes(s.Reserved));
                Row("已提交", FormatBytes(s.Committed));
            }
        }

        if (s.AllocatableGranules == 0)
        {
            ImGui.TextColored(
                ImGuiColors.DalamudRed,
                "此窗口范围内没有空闲的 64 KB 槽位，无法为此处的 Hook 分配范围内跳板。"u8);
        }
        else if (s.AllocatableGranules < 16)
        {
            ImGui.TextColored(
                ImGuiColors.DalamudOrange,
                $"此窗口范围内仅剩 {s.AllocatableGranules} 个槽位");
        }

        return;

        static void Row(string label, string value)
        {
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.TextUnformatted(label);
            ImGui.TableNextColumn();
            ImGui.TextUnformatted(value);
        }
    }

    private void DrawFreeBlocks()
    {
        if (this.stats.WindowSize == 0)
            return;

        ImGui.Text("窗口范围内最大的空闲块"u8);

        var blocks = this.regions
                         .Where(x => (x.State & MEM.MEM_FREE) != 0)
                         .Select(x => (Start: Math.Max(x.Start, this.stats.WindowStart), End: Math.Min(x.End, this.stats.WindowEnd)))
                         .Where(x => x.End > x.Start)
                         .Select(x => (x.Start, x.End, Granules: CountGranules(x.Start, x.End).Count))
                         .OrderByDescending(x => x.Granules)
                         .Take(20)
                         .ToList();

        using var table = ImRaii.Table("##addressSpaceFree"u8, 4, ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders, new Vector2(0, 200));
        if (!table.Success)
            return;

        ImGui.TableSetupColumn("起始地址"u8);
        ImGui.TableSetupColumn("结束地址"u8);
        ImGui.TableSetupColumn("大小"u8);
        ImGui.TableSetupColumn("64 KB 槽位"u8);
        ImGui.TableHeadersRow();

        foreach (var block in blocks)
        {
            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.TextUnformatted($"0x{block.Start:X}");
            ImGui.TableNextColumn();
            ImGui.TextUnformatted($"0x{block.End:X}");
            ImGui.TableNextColumn();
            ImGui.TextUnformatted(FormatBytes(block.End - block.Start));
            ImGui.TableNextColumn();
            ImGui.TextUnformatted(block.Granules.ToString());
        }
    }

    private void DumpToLog()
    {
        var s = this.stats;
        var sb = new StringBuilder();

        sb.AppendLine($"地址空间映射 ({this.regions.Count} 个区域)");

        if (s.WindowSize != 0)
        {
            var allocatable = s.AllocatableGranules * Granularity;
            sb.AppendLine(
                $"0x{s.Anchor:X} 周围的窗口：0x{s.WindowStart:X}-0x{s.WindowEnd:X}，" +
                $"可分配 {allocatable}（{s.AllocatableGranules} 个粒度块），空闲 {s.Free}，" +
                $"已保留 {s.Reserved}，已提交 {s.Committed}，最大连续空间 {s.LargestFreeRun}");
        }

        foreach (var region in this.regions)
        {
            var state = (region.State & MEM.MEM_FREE) != 0 ? "空闲" :
                        (region.State & MEM.MEM_COMMIT) != 0 ? "提交" : "保留";
            sb.AppendLine($"0x{region.Start:X16}-0x{region.End:X16} {region.Size,16} {state,-8} 保护=0x{region.Protect:X}");
        }

        Log.Information("{Map}", sb.ToString());
    }

    private readonly record struct Region(ulong Start, ulong Size, uint State, uint Protect)
    {
        public ulong End => this.Start + this.Size;
    }

    private readonly record struct AnchorChoice(string Name, ulong Address);

    private struct WindowStats
    {
        public ulong Anchor;
        public ulong WindowStart;
        public ulong WindowEnd;
        public ulong WindowSize;
        public ulong Free;
        public ulong Reserved;
        public ulong Committed;
        public ulong AllocatableGranules;
        public ulong LargestFreeRun;
    }
}
