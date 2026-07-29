using System.Buffers.Binary;
using System.Numerics;
using System.Text;

using Dalamud.Bindings.ImGui;
using Dalamud.Data;
using Dalamud.Game.Inventory;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Textures.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Utility;

using FFXIVClientStructs.FFXIV.Client.Game;

using Lumina.Excel.Sheets;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying inventory data.
/// </summary>
internal class InventoryWidget : IDataWindowWidget
{
    private const ImGuiTableFlags TableFlags = ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders |
                                               ImGuiTableFlags.ScrollY | ImGuiTableFlags.NoSavedSettings;

    private const ImGuiTableFlags InnerTableFlags = ImGuiTableFlags.BordersInner | ImGuiTableFlags.NoSavedSettings;

    private DataManager dataManager;
    private TextureManager textureManager;
    private GameInventoryType? selectedInventoryType = GameInventoryType.Inventory1;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["inv", "inventory"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "物品栏";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        this.dataManager ??= Service<DataManager>.Get();
        this.textureManager ??= Service<TextureManager>.Get();

        this.DrawInventoryTypeList();

        if (this.selectedInventoryType == null)
            return;

        ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);

        this.DrawInventoryType(this.selectedInventoryType.Value);
    }

    private static string StripSoftHypen(string input)
    {
        return input.Replace("\u00AD", string.Empty);
    }

    private unsafe void DrawInventoryTypeList()
    {
        using var table = ImRaii.Table("InventoryTypeTable"u8, 2, TableFlags, new Vector2(300, -1));
        if (!table) return;

        ImGui.TableSetupColumn("类型"u8);
        ImGui.TableSetupColumn("大小"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupScrollFreeze(2, 1);
        ImGui.TableHeadersRow();

        foreach (var inventoryType in Enum.GetValues<GameInventoryType>())
        {
            var items = GameInventoryItem.GetReadOnlySpanOfInventory(inventoryType);

            using var itemDisabled = ImRaii.Disabled(items.IsEmpty);

            ImGui.TableNextRow();
            ImGui.TableNextColumn(); // Type
            if (ImGui.Selectable(inventoryType.ToString(), this.selectedInventoryType == inventoryType, ImGuiSelectableFlags.SpanAllColumns))
            {
                this.selectedInventoryType = inventoryType;
            }

            using (var contextMenu = ImRaii.ContextPopupItem($"##InventoryContext{inventoryType}"))
            {
                if (contextMenu)
                {
                    if (ImGui.MenuItem("复制名称"u8))
                    {
                        ImGui.SetClipboardText(inventoryType.ToString());
                    }

                    if (ImGui.MenuItem("复制地址"u8))
                    {
                        var container = InventoryManager.Instance()->GetInventoryContainer((InventoryType)inventoryType);
                        ImGui.SetClipboardText($"0x{(nint)container:X}");
                    }
                }
            }

            ImGui.TableNextColumn(); // Size
            ImGui.Text(items.Length.ToString());
        }
    }

    private void DrawInventoryType(GameInventoryType inventoryType)
    {
        var items = GameInventoryItem.GetReadOnlySpanOfInventory(inventoryType);
        if (items.IsEmpty)
        {
            ImGui.Text($"{inventoryType} 为空。");
            return;
        }

        using var itemTable = ImRaii.Table("InventoryItemTable"u8, 4, TableFlags);
        if (!itemTable) return;

        ImGui.TableSetupColumn("格位"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupColumn("物品 ID"u8, ImGuiTableColumnFlags.WidthFixed, 70);
        ImGui.TableSetupColumn("数量"u8, ImGuiTableColumnFlags.WidthFixed, 70);
        ImGui.TableSetupColumn("物品"u8);
        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableHeadersRow();

        for (var slotIndex = 0; slotIndex < items.Length; slotIndex++)
        {
            var item = items[slotIndex];

            using var disabledItem = ImRaii.Disabled(item.ItemId == 0);

            ImGui.TableNextRow();
            ImGui.TableNextColumn(); // Slot
            ImGui.Text(slotIndex.ToString());

            ImGui.TableNextColumn(); // ItemId
            ImGuiHelpers.ClickToCopyText(item.ItemId.ToString());

            ImGui.TableNextColumn(); // Quantity
            ImGuiHelpers.ClickToCopyText(item.Quantity.ToString());

            ImGui.TableNextColumn(); // Item
            if (item.ItemId != 0 && item.Quantity != 0)
            {
                var itemName = ItemUtil.GetItemName(item.ItemId).ExtractText();
                var iconId = this.GetItemIconId(item.ItemId);

                if (this.textureManager.Shared.TryGetFromGameIcon(new GameIconLookup(iconId, item.IsHq), out var tex) && tex.TryGetWrap(out var texture, out _))
                {
                    ImGui.Image(texture.Handle, new Vector2(ImGui.GetTextLineHeight()));

                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetMouseCursor(ImGuiMouseCursor.Hand);

                        using var tooltip = ImRaii.Tooltip();
                        ImGui.Text("单击复制 IconId"u8);
                        ImGui.Text($"ID：{iconId} - 尺寸：{texture.Width}x{texture.Height}");
                        ImGui.Image(texture.Handle, new(texture.Width, texture.Height));
                    }

                    if (ImGui.IsItemClicked())
                        ImGui.SetClipboardText(iconId.ToString());
                }

                ImGui.SameLine();

                using var itemNameColor = ImRaii.PushColor(ImGuiCol.Text, this.GetItemRarityColor(item.ItemId));
                using var node = ImRaii.TreeNode($"{itemName}###{inventoryType}_{slotIndex}", ImGuiTreeNodeFlags.SpanAvailWidth);
                itemNameColor.Pop();

                using (var contextMenu = ImRaii.ContextPopupItem($"{inventoryType}_{slotIndex}_ContextMenu"))
                {
                    if (contextMenu)
                    {
                        if (ImGui.MenuItem("复制名称"u8))
                        {
                            ImGui.SetClipboardText(itemName);
                        }
                    }
                }

                if (!node) continue;

                using var itemInfoTable = ImRaii.Table($"{inventoryType}_{slotIndex}_Table", 2, InnerTableFlags);
                if (!itemInfoTable) continue;

                ImGui.TableSetupColumn("名称"u8, ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("值"u8);
                // ImGui.TableHeadersRow();

                static void AddKeyValueRow(string fieldName, string value)
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text(fieldName);
                    ImGui.TableNextColumn();
                    ImGuiHelpers.ClickToCopyText(value);
                }

                static void AddValueValueRow(string value1, string value2)
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGuiHelpers.ClickToCopyText(value1);
                    ImGui.TableNextColumn();
                    ImGuiHelpers.ClickToCopyText(value2);
                }

                AddKeyValueRow("物品 ID", item.ItemId.ToString());
                AddKeyValueRow("数量", item.Quantity.ToString());
                AddKeyValueRow("投影 ID", item.GlamourId.ToString());

                if (!ItemUtil.IsEventItem(item.ItemId))
                {
                    AddKeyValueRow(item.IsCollectable ? "收藏价值" : "精炼度", item.SpiritbondOrCollectability.ToString());

                    if (item.CrafterContentId != 0)
                        AddKeyValueRow("制作者内容 ID", item.CrafterContentId.ToString());
                }

                var flagsBuilder = new StringBuilder();

                if (item.IsHq)
                {
                    flagsBuilder.Append("高品质（IsHq）");
                }

                if (item.IsCompanyCrestApplied)
                {
                    if (flagsBuilder.Length != 0)
                        flagsBuilder.Append(", ");

                    flagsBuilder.Append("已应用部队纹章（IsCompanyCrestApplied）");
                }

                if (item.IsRelic)
                {
                    if (flagsBuilder.Length != 0)
                        flagsBuilder.Append(", ");

                    flagsBuilder.Append("古武（IsRelic）");
                }

                if (item.IsCollectable)
                {
                    if (flagsBuilder.Length != 0)
                        flagsBuilder.Append(", ");

                    flagsBuilder.Append("收藏品（IsCollectable）");
                }

                if (flagsBuilder.Length == 0)
                    flagsBuilder.Append("无");

                AddKeyValueRow("标志", flagsBuilder.ToString());

                if (ItemUtil.IsNormalItem(item.ItemId) && this.dataManager.Excel.GetSheet<Item>().TryGetRow(item.ItemId, out var itemRow))
                {
                    if (itemRow.DyeCount > 0 && item.Stains.Length > 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("染剂"u8);
                        ImGui.TableNextColumn();

                        using var stainTable = ImRaii.Table($"{inventoryType}_{slotIndex}_StainTable", 2, InnerTableFlags);
                        if (!stainTable) continue;

                        ImGui.TableSetupColumn("染剂 ID"u8, ImGuiTableColumnFlags.WidthFixed, 80);
                        ImGui.TableSetupColumn("名称"u8);
                        ImGui.TableHeadersRow();

                        for (var i = 0; i < itemRow.DyeCount; i++)
                        {
                            var stainId = item.Stains[i];
                            AddValueValueRow(stainId.ToString(), this.GetStainName(stainId));
                        }
                    }

                    if (itemRow.MateriaSlotCount > 0 && item.Materia.Length > 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text("魔晶石"u8);
                        ImGui.TableNextColumn();

                        using var materiaTable = ImRaii.Table($"{inventoryType}_{slotIndex}_MateriaTable", 2, InnerTableFlags);
                        if (!materiaTable) continue;

                        ImGui.TableSetupColumn("魔晶石 ID"u8, ImGuiTableColumnFlags.WidthFixed, 80);
                        ImGui.TableSetupColumn("魔晶石等级 ID"u8);
                        ImGui.TableHeadersRow();

                        for (var i = 0; i < Math.Min(itemRow.MateriaSlotCount, item.Materia.Length); i++)
                        {
                            AddValueValueRow(item.Materia[i].ToString(), item.MateriaGrade[i].ToString());
                        }
                    }
                }
            }
        }
    }

    private string GetStainName(uint stainId)
    {
        return this.dataManager.Excel.GetSheet<Stain>().TryGetRow(stainId, out var stainRow)
            ? StripSoftHypen(stainRow.Name.ExtractText())
            : $"染剂 #{stainId}";
    }

    private uint GetItemRarityColor(uint itemId, bool isEdgeColor = false)
    {
        var normalized = ItemUtil.GetBaseId(itemId);

        if (normalized.Kind == ItemKind.EventItem)
            return isEdgeColor ? 0xFF000000 : 0xFFFFFFFF;

        if (!this.dataManager.Excel.GetSheet<Item>().TryGetRow(normalized.ItemId, out var item))
            return isEdgeColor ? 0xFF000000 : 0xFFFFFFFF;

        var rowId = ItemUtil.GetItemRarityColorType(item.RowId, isEdgeColor);
        return this.dataManager.Excel.GetSheet<UIColor>().TryGetRow(rowId, out var color)
            ? BinaryPrimitives.ReverseEndianness(color.Dark) | 0xFF000000
            : 0xFFFFFFFF;
    }

    private uint GetItemIconId(uint itemId)
    {
        var normalized = ItemUtil.GetBaseId(itemId);

        // EventItem
        if (normalized.Kind == ItemKind.EventItem)
            return this.dataManager.Excel.GetSheet<EventItem>().TryGetRow(itemId, out var eventItem) ? eventItem.Icon : 0u;

        return this.dataManager.Excel.GetSheet<Item>().TryGetRow(normalized.ItemId, out var item) ? item.Icon : 0u;
    }
}
