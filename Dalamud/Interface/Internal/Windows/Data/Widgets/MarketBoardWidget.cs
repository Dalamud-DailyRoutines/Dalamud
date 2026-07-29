using System.Collections.Concurrent;
using System.Globalization;

using Dalamud.Bindings.ImGui;
using Dalamud.Game.MarketBoard;
using Dalamud.Game.Network.Structures;
using Dalamud.Interface.Utility.Raii;

using ImGuiTable = Dalamud.Interface.Utility.ImGuiTable;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget to display market board events.
/// </summary>
internal class MarketBoardWidget : IDataWindowWidget
{
    private const ImGuiTableFlags TableFlags = ImGuiTableFlags.SizingFixedFit | ImGuiTableFlags.RowBg;

    private readonly ConcurrentQueue<(IMarketBoardHistory MarketBoardHistory, IMarketBoardHistoryListing Listing)> marketBoardHistoryQueue = new();
    private readonly ConcurrentQueue<(IMarketBoardCurrentOfferings MarketBoardCurrentOfferings, IMarketBoardItemListing Listing)> marketBoardCurrentOfferingsQueue = new();
    private readonly ConcurrentQueue<IMarketBoardPurchase> marketBoardPurchasesQueue = new();
    private readonly ConcurrentQueue<IMarketBoardPurchaseHandler> marketBoardPurchaseRequestsQueue = new();
    private readonly ConcurrentQueue<IMarketTaxRates> marketTaxRatesQueue = new();

    private bool trackMarketBoard;
    private int trackedEvents;

    /// <summary> Finalizes an instance of the <see cref="MarketBoardWidget"/> class. </summary>
    ~MarketBoardWidget()
    {
        if (this.trackMarketBoard)
        {
            this.trackMarketBoard = false;
            var marketBoard = Service<MarketBoard>.GetNullable();
            if (marketBoard != null)
            {
                marketBoard.HistoryReceived -= this.MarketBoardHistoryReceived;
                marketBoard.OfferingsReceived -= this.MarketBoardOfferingsReceived;
                marketBoard.ItemPurchased -= this.MarketBoardItemPurchased;
                marketBoard.PurchaseRequested -= this.MarketBoardPurchaseRequested;
                marketBoard.TaxRatesReceived -= this.TaxRatesReceived;
            }
        }
    }

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["marketboard"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "市场布告板";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.trackMarketBoard = false;
        this.trackedEvents = 1;
        this.marketBoardHistoryQueue.Clear();
        this.marketBoardPurchaseRequestsQueue.Clear();
        this.marketBoardPurchasesQueue.Clear();
        this.marketTaxRatesQueue.Clear();
        this.marketBoardCurrentOfferingsQueue.Clear();
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var marketBoard = Service<MarketBoard>.Get();
        if (ImGui.Checkbox("跟踪市场布告板事件"u8, ref this.trackMarketBoard))
        {
            if (this.trackMarketBoard)
            {
                marketBoard.HistoryReceived += this.MarketBoardHistoryReceived;
                marketBoard.OfferingsReceived += this.MarketBoardOfferingsReceived;
                marketBoard.ItemPurchased += this.MarketBoardItemPurchased;
                marketBoard.PurchaseRequested += this.MarketBoardPurchaseRequested;
                marketBoard.TaxRatesReceived += this.TaxRatesReceived;
            }
            else
            {
                marketBoard.HistoryReceived -= this.MarketBoardHistoryReceived;
                marketBoard.OfferingsReceived -= this.MarketBoardOfferingsReceived;
                marketBoard.ItemPurchased -= this.MarketBoardItemPurchased;
                marketBoard.PurchaseRequested -= this.MarketBoardPurchaseRequested;
                marketBoard.TaxRatesReceived -= this.TaxRatesReceived;
            }
        }

        ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X / 2);
        if (ImGui.DragInt("保留的事件数量"u8, ref this.trackedEvents, 0.1f, 1, 512))
        {
            this.trackedEvents = Math.Clamp(this.trackedEvents, 1, 512);
        }

        if (ImGui.Button("清空已保留的事件"u8))
        {
            this.marketBoardHistoryQueue.Clear();
        }

        using var tabBar = ImRaii.TabBar("marketTabs"u8);
        if (!tabBar.Success)
            return;

        using (var tabItem = ImRaii.TabItem("成交历史"u8))
        {
            if (tabItem)
            {
                ImGuiTable.DrawTable("history-table", this.marketBoardHistoryQueue, this.DrawMarketBoardHistory, TableFlags, "物品 ID", "数量", "高品质", "成交价", "买家名称", "购买时间");
            }
        }

        using (var tabItem = ImRaii.TabItem("在售列表"u8))
        {
            if (tabItem)
            {
                ImGuiTable.DrawTable("offerings-table", this.marketBoardCurrentOfferingsQueue, this.DrawMarketBoardCurrentOfferings, TableFlags, "物品 ID", "数量", "高品质", "单价", "雇员名称");
            }
        }

        using (var tabItem = ImRaii.TabItem("购买记录"u8))
        {
            if (tabItem)
            {
                ImGuiTable.DrawTable("purchases-table", this.marketBoardPurchasesQueue, this.DrawMarketBoardPurchases, TableFlags, "物品 ID", "数量");
            }
        }

        using (var tabItem = ImRaii.TabItem("购买请求"u8))
        {
            if (tabItem)
            {
                ImGuiTable.DrawTable("requests-table", this.marketBoardPurchaseRequestsQueue, this.DrawMarketBoardPurchaseRequests, TableFlags, "物品 ID", "高品质", "数量", "单价", "税金总额", "城市 ID", "商品 ID", "雇员 ID");
            }
        }

        using (var tabItem = ImRaii.TabItem("税率"u8))
        {
            if (tabItem)
            {
                ImGuiTable.DrawTable("taxes-table", this.marketTaxRatesQueue, this.DrawMarketTaxRates, TableFlags, "乌尔达哈", "利姆萨·罗敏萨", "格里达尼亚", "伊修加德", "黄金港", "水晶都", "旧萨雷安", "图莱尤拉", "有效期至");
            }
        }
    }

    private void TaxRatesReceived(IMarketTaxRates marketTaxRates)
    {
        this.marketTaxRatesQueue.Enqueue(marketTaxRates);

        while (this.marketTaxRatesQueue.Count > this.trackedEvents)
        {
            this.marketTaxRatesQueue.TryDequeue(out _);
        }
    }

    private void MarketBoardPurchaseRequested(IMarketBoardPurchaseHandler marketBoardPurchaseHandler)
    {
        this.marketBoardPurchaseRequestsQueue.Enqueue(marketBoardPurchaseHandler);

        while (this.marketBoardPurchaseRequestsQueue.Count > this.trackedEvents)
        {
            this.marketBoardPurchaseRequestsQueue.TryDequeue(out _);
        }
    }

    private void MarketBoardItemPurchased(IMarketBoardPurchase marketBoardPurchase)
    {
        this.marketBoardPurchasesQueue.Enqueue(marketBoardPurchase);

        while (this.marketBoardPurchasesQueue.Count > this.trackedEvents)
        {
            this.marketBoardPurchasesQueue.TryDequeue(out _);
        }
    }

    private void MarketBoardOfferingsReceived(IMarketBoardCurrentOfferings marketBoardCurrentOfferings)
    {
        foreach (var listing in marketBoardCurrentOfferings.ItemListings)
        {
            this.marketBoardCurrentOfferingsQueue.Enqueue((marketBoardCurrentOfferings, listing));
        }

        while (this.marketBoardCurrentOfferingsQueue.Count > this.trackedEvents)
        {
            this.marketBoardCurrentOfferingsQueue.TryDequeue(out _);
        }
    }

    private void MarketBoardHistoryReceived(IMarketBoardHistory marketBoardHistory)
    {
        foreach (var listing in marketBoardHistory.HistoryListings)
        {
            this.marketBoardHistoryQueue.Enqueue((marketBoardHistory, listing));
        }

        while (this.marketBoardHistoryQueue.Count > this.trackedEvents)
        {
            this.marketBoardHistoryQueue.TryDequeue(out _);
        }
    }

    private void DrawMarketBoardHistory((IMarketBoardHistory History, IMarketBoardHistoryListing Listing) data)
    {
        ImGui.TableNextColumn();
        ImGui.Text(data.History.ItemId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.Quantity.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.IsHq ? "是" : "否");

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.SalePrice.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.BuyerName);

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.PurchaseTime.ToString(CultureInfo.InvariantCulture));
    }

    private void DrawMarketBoardCurrentOfferings((IMarketBoardCurrentOfferings MarketBoardCurrentOfferings, IMarketBoardItemListing Listing) data)
    {
        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.ItemId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.ItemQuantity.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.IsHq ? "是" : "否");

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.PricePerUnit.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.Listing.RetainerName);
    }

    private void DrawMarketBoardPurchases(IMarketBoardPurchase data)
    {
        ImGui.TableNextColumn();
        ImGui.Text(data.CatalogId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.ItemQuantity.ToString());
    }

    private void DrawMarketBoardPurchaseRequests(IMarketBoardPurchaseHandler data)
    {
        ImGui.TableNextColumn();
        ImGui.Text(data.CatalogId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.IsHq ? "是" : "否");

        ImGui.TableNextColumn();
        ImGui.Text(data.ItemQuantity.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.PricePerUnit.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.TotalTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.RetainerCityId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.ListingId.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.RetainerId.ToString());
    }

    private void DrawMarketTaxRates(IMarketTaxRates data)
    {
        ImGui.TableNextColumn();
        ImGui.Text(data.UldahTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.LimsaLominsaTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.GridaniaTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.IshgardTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.KuganeTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.CrystariumTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.SharlayanTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.TuliyollalTax.ToString());

        ImGui.TableNextColumn();
        ImGui.Text(data.ValidUntil.ToString(CultureInfo.InvariantCulture));
    }
}
