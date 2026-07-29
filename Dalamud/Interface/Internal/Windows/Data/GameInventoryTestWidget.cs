using System.Collections.Generic;

using Dalamud.Bindings.ImGui;
using Dalamud.Configuration.Internal;
using Dalamud.Game.Inventory;
using Dalamud.Game.Inventory.InventoryEventArgTypes;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Logging.Internal;

using Serilog.Events;

namespace Dalamud.Interface.Internal.Windows.Data;

/// <summary>
/// Tester for <see cref="GameInventory"/>.
/// </summary>
internal class GameInventoryTestWidget : IDataWindowWidget
{
    private static readonly ModuleLog Log = ModuleLog.Create<GameInventoryTestWidget>();

    private GameInventoryPluginScoped? scoped;
    private bool standardEnabled;
    private bool rawEnabled;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["gameinventorytest"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "GameInventory 测试";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load() => this.Ready = true;

    /// <inheritdoc/>
    public void Draw()
    {
        if (Service<DalamudConfiguration>.Get().LogLevel > LogEventLevel.Information)
        {
            ImGui.TextColoredWrapped(
                ImGuiColors.AttentionForeground,
                "请启用 LogLevel=Information 显示以查看日志。"u8);
        }

        using var table = ImRaii.Table(this.DisplayName, 3, ImGuiTableFlags.SizingFixedFit);
        if (!table.Success)
            return;

        ImGui.TableNextColumn();
        ImGui.Text("标准日志"u8);

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(this.standardEnabled))
        {
            if (ImGui.Button("启用##standard-enable"u8) && !this.standardEnabled)
            {
                this.scoped ??= new();
                this.scoped.InventoryChanged += ScopedOnInventoryChanged;
                this.standardEnabled = true;
            }
        }

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(!this.standardEnabled))
        {
            if (ImGui.Button("禁用##standard-disable"u8) && this.scoped is not null && this.standardEnabled)
            {
                this.scoped.InventoryChanged -= ScopedOnInventoryChanged;
                this.standardEnabled = false;
                if (!this.rawEnabled)
                {
                    ((IInternalDisposableService)this.scoped).DisposeService();
                    this.scoped = null;
                }
            }
        }

        ImGui.TableNextRow();

        ImGui.TableNextColumn();
        ImGui.Text("原始日志"u8);

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(this.rawEnabled))
        {
            if (ImGui.Button("启用##raw-enable"u8) && !this.rawEnabled)
            {
                this.scoped ??= new();
                this.scoped.InventoryChangedRaw += ScopedOnInventoryChangedRaw;
                this.rawEnabled = true;
            }
        }

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(!this.rawEnabled))
        {
            if (ImGui.Button("禁用##raw-disable"u8) && this.scoped is not null && this.rawEnabled)
            {
                this.scoped.InventoryChangedRaw -= ScopedOnInventoryChangedRaw;
                this.rawEnabled = false;
                if (!this.standardEnabled)
                {
                    ((IInternalDisposableService)this.scoped).DisposeService();
                    this.scoped = null;
                }
            }
        }

        ImGui.TableNextRow();

        ImGui.TableNextColumn();
        ImGui.Text("全部"u8);

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(this.standardEnabled && this.rawEnabled))
        {
            if (ImGui.Button("启用##all-enable"u8))
            {
                this.scoped ??= new();
                if (!this.standardEnabled)
                    this.scoped.InventoryChanged += ScopedOnInventoryChanged;
                if (!this.rawEnabled)
                    this.scoped.InventoryChangedRaw += ScopedOnInventoryChangedRaw;
                this.standardEnabled = this.rawEnabled = true;
            }
        }

        ImGui.TableNextColumn();
        using (ImRaii.Disabled(this.scoped is null))
        {
            if (ImGui.Button("禁用##all-disable"u8))
            {
                ((IInternalDisposableService)this.scoped)?.DisposeService();
                this.scoped = null;
                this.standardEnabled = this.rawEnabled = false;
            }
        }
    }

    private static void ScopedOnInventoryChangedRaw(IReadOnlyCollection<InventoryEventArgs> events)
    {
        var i = 0;
        foreach (var e in events)
            Log.Information($"[{++i}/{events.Count}] 原始事件：{e}");
    }

    private static void ScopedOnInventoryChanged(IReadOnlyCollection<InventoryEventArgs> events)
    {
        var i = 0;
        foreach (var e in events)
        {
            if (e is InventoryComplexEventArgs icea)
                Log.Information($"[{++i}/{events.Count}] {icea}\n\t├ {icea.SourceEvent}\n\t└ {icea.TargetEvent}");
            else
                Log.Information($"[{++i}/{events.Count}] {e}");
        }
    }
}
