using System.Collections.Concurrent;
using System.Threading;

using Dalamud.Bindings.ImGui;
using Dalamud.Hooking;
using Dalamud.Interface.Components;
using Dalamud.Interface.Utility.Raii;

using FFXIVClientStructs.FFXIV.Application.Network;
using FFXIVClientStructs.FFXIV.Client.Game;
using FFXIVClientStructs.FFXIV.Client.Game.Object;
using FFXIVClientStructs.FFXIV.Client.Game.UI;
using FFXIVClientStructs.FFXIV.Client.Network;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget to display the current packets.
/// </summary>
internal unsafe class NetworkMonitorWidget : IDataWindowWidget
{
    private readonly ConcurrentQueue<NetworkPacketData> packets = new();

    private Hook<PacketDispatcher.Delegates.OnReceivePacket>? hookZoneDown;
    private Hook<ZoneClient.Delegates.SendPacket>? hookZoneUp;

    private bool trackZoneUp;
    private bool trackZoneDown;
    private int trackedPackets = 20;
    private ulong nextPacketIndex;
    private string filterString = string.Empty;
    private bool filterRecording = true;
    private bool autoScroll = true;
    private bool autoScrollPending;

    /// <summary> Finalizes an instance of the <see cref="NetworkMonitorWidget"/> class. </summary>
    ~NetworkMonitorWidget()
    {
        this.hookZoneDown?.Dispose();
        this.hookZoneUp?.Dispose();
    }

    private enum NetworkMessageDirection
    {
        ZoneDown,
        ZoneUp,
    }

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["network", "netmon", "networkmonitor"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "网络监视器";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load() => this.Ready = true;

    /// <inheritdoc/>
    public void Draw()
    {
        this.hookZoneDown ??= Hook<PacketDispatcher.Delegates.OnReceivePacket>.FromAddress(
            (nint)PacketDispatcher.StaticVirtualTablePointer->OnReceivePacket,
            this.OnReceivePacketDetour);

        this.hookZoneUp ??= Hook<ZoneClient.Delegates.SendPacket>.FromAddress(
            (nint)ZoneClient.MemberFunctionPointers.SendPacket,
            this.SendPacketDetour);

        if (ImGui.Checkbox("跟踪 ZoneUp"u8, ref this.trackZoneUp))
        {
            if (this.trackZoneUp)
            {
                if (!this.trackZoneDown)
                    this.nextPacketIndex = 0;

                this.hookZoneUp?.Enable();
            }
            else
            {
                this.hookZoneUp?.Disable();
            }
        }

        if (ImGui.Checkbox("跟踪 ZoneDown"u8, ref this.trackZoneDown))
        {
            if (this.trackZoneDown)
            {
                if (!this.trackZoneUp)
                    this.nextPacketIndex = 0;

                this.hookZoneDown?.Enable();
            }
            else
            {
                this.hookZoneDown?.Disable();
            }
        }

        ImGui.SetNextItemWidth(-1);
        if (ImGui.DragInt("保留的数据包数量"u8, ref this.trackedPackets, 0.1f, 1, 512))
        {
            this.trackedPackets = Math.Clamp(this.trackedPackets, 1, 512);
        }

        if (ImGui.Button("清空已保留的数据包"u8))
        {
            this.packets.Clear();
            this.nextPacketIndex = 0;
        }

        ImGui.SameLine();
        ImGui.Checkbox("自动滚动"u8, ref this.autoScroll);

        ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X - (ImGui.GetStyle().ItemInnerSpacing.X + ImGui.GetFrameHeight()) * 2);
        ImGui.InputTextWithHint("##Filter"u8, "筛选操作码..."u8, ref this.filterString, 1024, ImGuiInputTextFlags.AutoSelectAll);
        ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);
        ImGui.Checkbox("##FilterRecording"u8, ref this.filterRecording);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("启用后，将先筛选数据包再记录。\n关闭后，将记录全部数据包，筛选条件仅影响表格中显示的数据包。"u8);
        ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);
        ImGuiComponents.HelpMarker("输入以逗号分隔的操作码列表。\n支持范围；在操作码前添加感叹号可将其排除。\n示例：-400,!50-100,650,700-980,!941");

        using var table = ImRaii.Table("NetworkMonitorTableV2"u8, 6, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg | ImGuiTableFlags.NoSavedSettings);
        if (!table) return;

        ImGui.TableSetupColumn("索引"u8, ImGuiTableColumnFlags.WidthFixed, 50);
        ImGui.TableSetupColumn("时间"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("方向"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("操作码"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("操作码（十六进制）"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("目标实体 ID"u8, ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableHeadersRow();

        var autoScrollDisabled = false;

        foreach (var packet in this.packets)
        {
            if (!this.filterRecording && !this.IsFiltered(packet.OpCode))
                continue;

            ImGui.TableNextColumn();
            ImGui.Text(packet.Index.ToString());

            ImGui.TableNextColumn();
            ImGui.Text(packet.Time.ToLongTimeString());

            ImGui.TableNextColumn();
            ImGui.Text(packet.Direction.ToString());

            ImGui.TableNextColumn();
            using (ImRaii.PushId(packet.Index.ToString()))
            {
                if (ImGui.SmallButton("X"))
                {
                    if (!string.IsNullOrEmpty(this.filterString))
                        this.filterString += ",";

                    this.filterString += $"!{packet.OpCode}";
                }
            }

            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("排除此操作码"u8);

            autoScrollDisabled |= ImGui.IsItemHovered();

            ImGui.SameLine();
            WidgetUtil.DrawCopyableText(packet.OpCode.ToString());
            autoScrollDisabled |= ImGui.IsItemHovered();

            ImGui.TableNextColumn();
            WidgetUtil.DrawCopyableText($"0x{packet.OpCode:X3}");
            autoScrollDisabled |= ImGui.IsItemHovered();

            ImGui.TableNextColumn();
            if (packet.TargetEntityId > 0)
            {
                WidgetUtil.DrawCopyableText($"{packet.TargetEntityId:X}");

                var name = !string.IsNullOrEmpty(packet.TargetName)
                    ? packet.TargetName
                    : GetTargetName(packet.TargetEntityId);

                if (!string.IsNullOrEmpty(name))
                {
                    ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);
                    ImGui.Text($"({name})");
                }
            }
        }

        if (this.autoScroll && this.autoScrollPending && !autoScrollDisabled)
        {
            ImGui.SetScrollHereY();
            this.autoScrollPending = false;
        }
    }

    private static string GetTargetName(uint targetId)
    {
        if (targetId == PlayerState.Instance()->EntityId)
            return "本地玩家";

        var cachedName = NameCache.Instance()->GetNameByEntityId(targetId);
        if (cachedName.HasValue)
            return cachedName.ToString();

        var obj = GameObjectManager.Instance()->Objects.GetObjectByEntityId(targetId);
        if (obj != null)
            return obj->NameString;

        return string.Empty;
    }

    private void OnReceivePacketDetour(PacketDispatcher* thisPtr, uint targetId, nint packet)
    {
        var opCode = *(ushort*)(packet + 2);
        var targetName = GetTargetName(targetId);
        this.RecordPacket(new NetworkPacketData(Interlocked.Increment(ref this.nextPacketIndex), DateTime.Now, opCode, NetworkMessageDirection.ZoneDown, targetId, targetName));
        this.hookZoneDown.OriginalDisposeSafe(thisPtr, targetId, packet);
    }

    private bool SendPacketDetour(ZoneClient* thisPtr, nint packet, uint a3, uint a4, bool a5)
    {
        var opCode = *(ushort*)packet;
        this.RecordPacket(new NetworkPacketData(Interlocked.Increment(ref this.nextPacketIndex), DateTime.Now, opCode, NetworkMessageDirection.ZoneUp, 0, string.Empty));
        return this.hookZoneUp.OriginalDisposeSafe(thisPtr, packet, a3, a4, a5);
    }

    private void RecordPacket(NetworkPacketData packet)
    {
        if (this.filterRecording && !this.IsFiltered(packet.OpCode))
            return;

        this.packets.Enqueue(packet);

        while (this.packets.Count > this.trackedPackets)
        {
            this.packets.TryDequeue(out _);
        }

        this.autoScrollPending = true;
    }

    private bool IsFiltered(ushort opcode)
    {
        var filterString = this.filterString.Replace(" ", string.Empty);

        if (filterString.Length == 0)
            return true;

        try
        {
            var offset = 0;
            var included = false;
            var hasInclude = false;

            while (filterString.Length - offset > 0)
            {
                var remaining = filterString[offset..];

                // find the end of the current entry
                var entryEnd = remaining.IndexOf(',');
                if (entryEnd == -1)
                    entryEnd = remaining.Length;

                var entry = filterString[offset..(offset + entryEnd)];
                var dash = entry.IndexOf('-');
                var isExcluded = entry.StartsWith('!');
                var startOffset = isExcluded ? 1 : 0;

                var entryMatch = dash == -1
                    ? ushort.Parse(entry[startOffset..]) == opcode
                    : ((dash - startOffset == 0 || opcode >= ushort.Parse(entry[startOffset..dash]))
                    && (entry[(dash + 1)..].Length == 0 || opcode <= ushort.Parse(entry[(dash + 1)..])));

                if (isExcluded)
                {
                    if (entryMatch)
                        return false;
                }
                else
                {
                    hasInclude = true;
                    included |= entryMatch;
                }

                if (entryEnd == filterString.Length)
                    break;

                offset += entryEnd + 1;
            }

            return !hasInclude || included;
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "无效的筛选字符串");
            return false;
        }
    }

#pragma warning disable SA1313
    private readonly record struct NetworkPacketData(ulong Index, DateTime Time, ushort OpCode, NetworkMessageDirection Direction, uint TargetEntityId, string TargetName);
#pragma warning restore SA1313
}
