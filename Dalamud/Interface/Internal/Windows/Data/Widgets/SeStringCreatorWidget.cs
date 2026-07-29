using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

using Dalamud.Bindings.ImGui;
using Dalamud.Data;
using Dalamud.Game;
using Dalamud.Game.ClientState;
using Dalamud.Game.Text.Evaluator;
using Dalamud.Game.Text.Noun.Enums;
using Dalamud.Game.Text.SeStringHandling;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Utility;

using FFXIVClientStructs.FFXIV.Client.System.String;
using FFXIVClientStructs.FFXIV.Client.UI;
using FFXIVClientStructs.FFXIV.Client.UI.Misc;
using FFXIVClientStructs.FFXIV.Component.Text;

using Lumina.Data;
using Lumina.Data.Files.Excel;
using Lumina.Data.Structs.Excel;
using Lumina.Excel;
using Lumina.Excel.Sheets;
using Lumina.Text.Expressions;
using Lumina.Text.Payloads;
using Lumina.Text.ReadOnly;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget to create SeStrings.
/// </summary>
internal class SeStringCreatorWidget : IDataWindowWidget
{
    private const LinkMacroPayloadType DalamudLinkType = (LinkMacroPayloadType)Payload.EmbeddedInfoType.DalamudLink - 1;

    private const ImGuiTableFlags TableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
                                               ImGuiTableFlags.ScrollY | ImGuiTableFlags.NoSavedSettings;

    private static readonly string[] TextEntryTypeOptions = ["String", "Macro", "Fixed"];

    private readonly Dictionary<MacroCode, string[]> expressionNames = new()
    {
        { MacroCode.SetResetTime, ["小时", "星期"] },
        { MacroCode.SetTime, ["时间"] },
        { MacroCode.If, ["条件", "条件为真时的语句", "条件为假时的语句"] },
        { MacroCode.Switch, ["条件"] },
        { MacroCode.PcName, ["实体 ID"] },
        { MacroCode.IfPcGender, ["实体 ID", "男性分支", "女性分支"] },
        { MacroCode.IfPcName, ["实体 ID", "匹配分支", "未匹配分支"] },
        // { MacroCode.Josa, [] },
        // { MacroCode.Josaro, [] },
        { MacroCode.IfSelf, ["实体 ID", "自身分支", "非自身分支"] },
        // { MacroCode.NewLine, [] },
        { MacroCode.Wait, ["秒数"] },
        { MacroCode.Icon, ["图标 ID"] },
        { MacroCode.Color, ["颜色"] },
        { MacroCode.EdgeColor, ["颜色"] },
        { MacroCode.ShadowColor, ["颜色"] },
        // { MacroCode.SoftHyphen, [] },
        // { MacroCode.Key, [] },
        // { MacroCode.Scale, [] },
        { MacroCode.Bold, ["是否启用"] },
        { MacroCode.Italic, ["是否启用"] },
        // { MacroCode.Edge, [] },
        // { MacroCode.Shadow, [] },
        // { MacroCode.NonBreakingSpace, [] },
        { MacroCode.Icon2, ["图标 ID"] },
        // { MacroCode.Hyphen, [] },
        { MacroCode.Num, ["值"] },
        { MacroCode.Hex, ["值"] },
        { MacroCode.Kilo, ["值", "分隔符"] },
        { MacroCode.Byte, ["值"] },
        { MacroCode.Sec, ["时间"] },
        { MacroCode.Time, ["值"] },
        { MacroCode.Float, ["值", "基数", "分隔符"] },
        { MacroCode.Link, ["类型"] },
        { MacroCode.Sheet, ["表名", "行 ID", "列索引", "列参数"] },
        { MacroCode.String, ["字符串"] },
        { MacroCode.Caps, ["字符串"] },
        { MacroCode.Head, ["字符串"] },
        { MacroCode.Split, ["字符串", "分隔符"] },
        { MacroCode.HeadAll, ["字符串"] },
        // { MacroCode.Fixed, [] },
        { MacroCode.Lower, ["字符串"] },
        { MacroCode.JaNoun, ["表名", "冠词类型", "行 ID", "数量", "格", "未知整数 5"] },
        { MacroCode.EnNoun, ["表名", "冠词类型", "行 ID", "数量", "格", "未知整数 5"] },
        { MacroCode.DeNoun, ["表名", "冠词类型", "行 ID", "数量", "格", "未知整数 5"] },
        { MacroCode.FrNoun, ["表名", "冠词类型", "行 ID", "数量", "格", "未知整数 5"] },
        { MacroCode.ChNoun, ["表名", "冠词类型", "行 ID", "数量", "格", "未知整数 5"] },
        { MacroCode.LowerHead, ["字符串"] },
        { MacroCode.SheetSub, ["表名", "行 ID", "子行 ID", "列索引", "次级表名", "次级表列索引"] },
        { MacroCode.ColorType, ["颜色类型"] },
        { MacroCode.EdgeColorType, ["颜色类型"] },
        { MacroCode.Ruby, ["正文", "注音"] },
        { MacroCode.Digit, ["值", "目标长度"] },
        { MacroCode.Ordinal, ["值"] },
        { MacroCode.Sound, ["是否为短音效", "音效 ID"] },
        { MacroCode.LevelPos, ["地点 ID"] },
    };

    private readonly Dictionary<LinkMacroPayloadType, string[]> linkExpressionNames = new()
    {
        { LinkMacroPayloadType.Character, ["标志", "世界 ID"] },
        { LinkMacroPayloadType.Item, ["物品 ID", "稀有度"] },
        { LinkMacroPayloadType.MapPosition, ["区域类型/地图 ID", "原始 X", "原始 Y"] },
        { LinkMacroPayloadType.Quest, ["行 ID"] },
        { LinkMacroPayloadType.Achievement, ["行 ID"] },
        { LinkMacroPayloadType.HowTo, ["行 ID"] },
        // PartyFinderNotification
        { LinkMacroPayloadType.Status, ["状态 ID"] },
        { LinkMacroPayloadType.PartyFinder, ["招募 ID", string.Empty, "世界 ID"] },
        { LinkMacroPayloadType.AkatsukiNote, ["行 ID"] },
        { LinkMacroPayloadType.Description, ["行 ID"] },
        { LinkMacroPayloadType.WKSPioneeringTrail, ["行 ID", "子行 ID"] },
        { LinkMacroPayloadType.MKDLore, ["行 ID"] },
        { DalamudLinkType, ["命令 ID", "附加值 1", "附加值 2", "附加字符串"] },
    };

    private readonly Dictionary<uint, string[]> fixedExpressionNames = new()
    {
        { 1, ["类型 0", "类型 1", "世界 ID"] },
        { 2, ["类型 0", "类型 1", "职业 ID", "等级"] },
        { 3, ["类型 0", "类型 1", "区域类型 ID", "副本与地图 ID", "原始 X", "原始 Y", "原始 Z", "地点名称 ID 覆盖值"] },
        { 4, ["类型 0", "类型 1", "物品 ID", "稀有度", string.Empty, string.Empty, "物品名称"] },
        { 5, ["类型 0", "类型 1", "音效 ID"] },
        { 6, ["类型 0", "类型 1", "对象字符串 ID"] },
        { 7, ["类型 0", "类型 1", "文本"] },
        { 8, ["类型 0", "类型 1", "秒数"] },
        { 9, ["类型 0", "类型 1", string.Empty] },
        { 10, ["类型 0", "类型 1", "状态 ID", "是否覆盖", "名称覆盖值", "描述覆盖值"] },
        { 11, ["类型 0", "类型 1", "招募 ID", string.Empty, "世界 ID", "跨界标志"] },
        { 12, ["类型 0", "类型 1", "任务 ID", string.Empty, string.Empty, string.Empty, "任务名称"] },
    };

    private readonly List<TextEntry> entries = [
        new TextEntry(TextEntryType.String, "欢迎使用 "),
        new TextEntry(TextEntryType.Macro, "<colortype(17)>"),
        new TextEntry(TextEntryType.Macro, "<edgecolortype(19)>"),
        new TextEntry(TextEntryType.String, "Dalamud"),
        new TextEntry(TextEntryType.Macro, "<edgecolor(stackcolor)>"),
        new TextEntry(TextEntryType.Macro, "<color(stackcolor)>"),
        new TextEntry(TextEntryType.Macro, " <string(lstr1)>"),
    ];

    private SeStringParameter[]? localParameters = [Versioning.GetScmVersion()];
    private ReadOnlySeString input;
    private ClientLanguage? language;
    private Task? validImportSheetNamesTask;
    private int importSelectedSheetName;
    private int importRowId;
    private string[]? validImportSheetNames;
    private float inputsWidth;
    private float lastContentWidth;

    private enum TextEntryType
    {
        String,
        Macro,
        Fixed,
    }

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = [];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "SeString 创建器";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.language = Service<ClientState>.Get().ClientLanguage;
        this.UpdateInputString(false);
        this.Ready = true;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        var contentWidth = ImGui.GetContentRegionAvail().X;

        // split panels in the middle by default
        if (this.inputsWidth == 0)
        {
            this.inputsWidth = contentWidth / 2f;
        }

        // resize panels relative to the window size
        if (contentWidth != this.lastContentWidth)
        {
            var originalWidth = this.lastContentWidth != 0 ? this.lastContentWidth : contentWidth;
            this.inputsWidth = (this.inputsWidth / originalWidth) * contentWidth;
            this.lastContentWidth = contentWidth;
        }

        using var tabBar = ImRaii.TabBar("SeStringCreatorWidgetTabBar"u8);
        if (!tabBar) return;

        this.DrawCreatorTab(contentWidth);
        this.DrawGlobalParametersTab();
    }

    private void DrawCreatorTab(float contentWidth)
    {
        using var tab = ImRaii.TabItem("创建器"u8);
        if (!tab) return;

        this.DrawControls();
        ImGui.Spacing();
        this.DrawInputs();

        this.localParameters ??= this.GetLocalParameters(this.input.AsSpan(), []);

        var evaluated = Service<SeStringEvaluator>.Get().Evaluate(
            this.input.AsSpan(),
            this.localParameters,
            this.language);

        ImGui.SameLine(0, 0);

        ImGui.Button("###InputPanelResizer"u8, new Vector2(4, -1));
        if (ImGui.IsItemActive())
        {
            this.inputsWidth += ImGui.GetIO().MouseDelta.X;
        }

        if (ImGui.IsItemHovered())
        {
            ImGui.SetMouseCursor(ImGuiMouseCursor.ResizeEw);

            if (ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
            {
                this.inputsWidth = contentWidth / 2f;
            }
        }

        ImGui.SameLine();

        using var child = ImRaii.Child("Preview"u8, new Vector2(ImGui.GetContentRegionAvail().X, -1));
        if (!child) return;

        if (this.localParameters!.Length != 0)
        {
            ImGui.Spacing();
            this.DrawParameters();
        }

        this.DrawPreview(evaluated);

        ImGui.Spacing();
        this.DrawPayloads(evaluated);
    }

    private unsafe void DrawGlobalParametersTab()
    {
        using var tab = ImRaii.TabItem("全局参数"u8);
        if (!tab) return;

        using var table = ImRaii.Table("GlobalParametersTable"u8, 5, TableFlags);
        if (!table) return;

        ImGui.TableSetupColumn("ID"u8, ImGuiTableColumnFlags.WidthFixed, 40);
        ImGui.TableSetupColumn("类型"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("值指针"u8, ImGuiTableColumnFlags.WidthFixed, 120);
        ImGui.TableSetupColumn("值"u8, ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("描述"u8, ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupScrollFreeze(5, 1);
        ImGui.TableHeadersRow();

        var deque = RaptureTextModule.Instance()->GlobalParameters;
        for (var i = 0u; i < deque.MySize; i++)
        {
            var item = deque[i];

            ImGui.TableNextRow();
            ImGui.TableNextColumn(); // Id
            ImGui.Text(i.ToString());

            ImGui.TableNextColumn(); // Type
            ImGui.Text(item.Type.ToString());

            ImGui.TableNextColumn(); // ValuePtr
            WidgetUtil.DrawCopyableText($"0x{(nint)item.ValuePtr:X}");

            ImGui.TableNextColumn(); // Value
            switch (item.Type)
            {
                case TextParameterType.Integer:
                    WidgetUtil.DrawCopyableText($"0x{item.IntValue:X}");
                    ImGui.SameLine();
                    WidgetUtil.DrawCopyableText(item.IntValue.ToString());
                    break;

                case TextParameterType.ReferencedUtf8String:
                    if (item.ReferencedUtf8StringValue != null)
                        WidgetUtil.DrawCopyableText(new ReadOnlySeStringSpan(item.ReferencedUtf8StringValue->Utf8String).ToString());
                    else
                        ImGui.Text("空"u8);

                    break;

                case TextParameterType.String:
                    if (item.StringValue.Value != null)
                        WidgetUtil.DrawCopyableText(item.StringValue.ToString());
                    else
                        ImGui.Text("空"u8);
                    break;
            }

            ImGui.TableNextColumn();
            ImGui.Text(i switch
            {
                0 => "玩家名称",
                1 => "临时实体 1：名称",
                2 => "临时实体 2：名称",
                3 => "玩家性别",
                4 => "临时实体 1：性别",
                5 => "临时实体 2：性别",
                6 => "临时实体 1：对象字符串 ID",
                7 => "临时实体 2：对象字符串 ID",
                10 => "艾欧泽亚时间：小时",
                11 => "艾欧泽亚时间：分钟",
                12 => "说话频道颜色（ColorSay）",
                13 => "喊话频道颜色（ColorShout）",
                14 => "悄悄话频道颜色（ColorTell）",
                15 => "小队频道颜色（ColorParty）",
                16 => "团队频道颜色（ColorAlliance）",
                17 => "通讯贝 1 频道颜色（ColorLS1）",
                18 => "通讯贝 2 频道颜色（ColorLS2）",
                19 => "通讯贝 3 频道颜色（ColorLS3）",
                20 => "通讯贝 4 频道颜色（ColorLS4）",
                21 => "通讯贝 5 频道颜色（ColorLS5）",
                22 => "通讯贝 6 频道颜色（ColorLS6）",
                23 => "通讯贝 7 频道颜色（ColorLS7）",
                24 => "通讯贝 8 频道颜色（ColorLS8）",
                25 => "部队频道颜色（ColorFCompany）",
                26 => "PvP 小队频道颜色（ColorPvPGroup）",
                27 => "PvP 小队公告颜色（ColorPvPGroupAnnounce）",
                28 => "新人频道颜色（ColorBeginner）",
                29 => "玩家情感动作颜色（ColorEmoteUser）",
                30 => "情感动作颜色（ColorEmote）",
                31 => "呼喊频道颜色（ColorYell）",
                32 => "部队公告颜色（ColorFCAnnounce）",
                33 => "新人频道公告颜色（ColorBeginnerAnnounce）",
                34 => "跨界通讯贝频道颜色（ColorCWLS）",
                35 => "攻击成功颜色（ColorAttackSuccess）",
                36 => "攻击失败颜色（ColorAttackFailure）",
                37 => "技能颜色（ColorAction）",
                38 => "物品颜色（ColorItem）",
                39 => "治疗颜色（ColorCureGive）",
                40 => "增益效果颜色（ColorBuffGive）",
                41 => "减益效果颜色（ColorDebuffGive）",
                42 => "回声颜色（ColorEcho）",
                43 => "系统消息颜色（ColorSysMsg）",
                51 => "玩家黑涡团军衔",
                52 => "玩家双蛇党军衔",
                53 => "玩家恒辉队军衔",
                54 => "搭档名称",
                55 => "任务内容名称",
                56 => "系统战斗消息颜色（ColorSysBattle）",
                57 => "系统采集消息颜色（ColorSysGathering）",
                58 => "系统错误消息颜色（ColorSysErr）",
                59 => "NPC 说话颜色（ColorNpcSay）",
                60 => "物品提示颜色（ColorItemNotice）",
                61 => "成长提示颜色（ColorGrowup）",
                62 => "战利品颜色（ColorLoot）",
                63 => "制作消息颜色（ColorCraft）",
                64 => "采集消息颜色（ColorGathering）",
                65 => "临时实体 1：名称以元音开头",
                66 => "临时实体 2：名称以元音开头",
                67 => "玩家职业 ID",
                68 => "玩家等级",
                69 => "玩家初始城市",
                70 => "玩家种族",
                71 => "玩家同步等级",
                73 => "任务 #66047：已遇见阿尔菲诺和阿莉塞",
                74 => "PlayStation 世代",
                75 => "是否为旧版玩家",
                77 => "客户端/平台？",
                78 => "玩家出生月份",
                79 => "手柄模式（PadMode）",
                82 => "数据中心地区",
                83 => "跨界通讯贝 2 频道颜色（ColorCWLS2）",
                84 => "跨界通讯贝 3 频道颜色（ColorCWLS3）",
                85 => "跨界通讯贝 4 频道颜色（ColorCWLS4）",
                86 => "跨界通讯贝 5 频道颜色（ColorCWLS5）",
                87 => "跨界通讯贝 6 频道颜色（ColorCWLS6）",
                88 => "跨界通讯贝 7 频道颜色（ColorCWLS7）",
                89 => "跨界通讯贝 8 频道颜色（ColorCWLS8）",
                91 => "玩家所属大国防联军",
                92 => "区域类型 ID",
                93 => "是否启用软键盘",
                94 => "职能颜色 1：防护职业（LogColorRoleTank）",
                95 => "职能颜色 2：防护职业（LogColorRoleTank）",
                96 => "职能颜色 1：治疗职业（LogColorRoleHealer）",
                97 => "职能颜色 2：治疗职业（LogColorRoleHealer）",
                98 => "职能颜色 1：进攻职业（LogColorRoleDPS）",
                99 => "职能颜色 2：进攻职业（LogColorRoleDPS）",
                100 => "职能颜色 1：其他职业（LogColorOtherClass）",
                101 => "职能颜色 2：其他职业（LogColorOtherClass）",
                102 => "是否拥有登录安全令牌",
                103 => "是否订阅 PlayStation Plus",
                104 => "手柄鼠标模式（PadMouseMode）",
                106 => "优遇世界加成最高等级",
                107 => "蜃景幻界辅助职业等级",
                108 => "深层迷宫 ID",
                _ => string.Empty,
            });
        }
    }

    private unsafe void DrawControls()
    {
        if (ImGui.Button("添加条目"u8))
        {
            this.entries.Add(new(TextEntryType.String, string.Empty));
        }

        ImGui.SameLine();

        if (ImGui.Button("从表格添加"u8))
        {
            ImGui.OpenPopup("AddFromSheetPopup"u8);
        }

        this.DrawAddFromSheetPopup();

        ImGui.SameLine();

        if (ImGui.Button("输出"u8))
        {
            var output = Utf8String.CreateEmpty();
            var temp = Utf8String.CreateEmpty();
            var temp2 = Utf8String.CreateEmpty();

            foreach (var entry in this.entries)
            {
                switch (entry.Type)
                {
                    case TextEntryType.String:
                        output->ConcatCStr(entry.Message);
                        break;

                    case TextEntryType.Macro:
                        temp->Clear();
                        RaptureTextModule.Instance()->MacroEncoder.EncodeString(temp, entry.Message);
                        output->Append(temp);
                        break;

                    case TextEntryType.Fixed:
                        temp->SetString(entry.Message);
                        temp2->Clear();

                        RaptureTextModule.Instance()->TextModule.ProcessMacroCode(temp2, temp->StringPtr);
                        var out1 = PronounModule.Instance()->ProcessString(temp2, true);
                        var out2 = PronounModule.Instance()->ProcessString(out1, false);

                        output->Append(out2);
                        break;
                }
            }

            RaptureLogModule.Instance()->PrintString(output->StringPtr);
            temp2->Dtor(true);
            temp->Dtor(true);
            output->Dtor(true);
        }

        ImGui.SameLine();

        if (ImGui.Button("输出求值结果"u8))
        {
            using var rssb = new RentedSeStringBuilder();

            foreach (var entry in this.entries)
            {
                switch (entry.Type)
                {
                    case TextEntryType.String:
                        rssb.Builder.Append(entry.Message);
                        break;

                    case TextEntryType.Macro:
                    case TextEntryType.Fixed:
                        rssb.Builder.AppendMacroString(entry.Message);
                        break;
                }
            }

            var evaluated = Service<SeStringEvaluator>.Get().Evaluate(
                rssb.Builder.ToReadOnlySeString(),
                this.localParameters,
                this.language);

            RaptureLogModule.Instance()->PrintString(evaluated);
        }

        if (this.entries.Count != 0)
        {
            ImGui.SameLine();

            if (ImGui.Button("复制宏字符串"u8))
            {
                using var rssb = new RentedSeStringBuilder();

                foreach (var entry in this.entries)
                {
                    switch (entry.Type)
                    {
                        case TextEntryType.String:
                            rssb.Builder.Append(entry.Message);
                            break;

                        case TextEntryType.Macro:
                        case TextEntryType.Fixed:
                            rssb.Builder.AppendMacroString(entry.Message);
                            break;
                    }
                }

                ImGui.SetClipboardText(rssb.Builder.ToReadOnlySeString().ToMacroString());
            }

            ImGui.SameLine();

            if (ImGui.Button("清空条目"u8))
            {
                this.entries.Clear();
                this.UpdateInputString();
            }
        }

        var raptureTextModule = RaptureTextModule.Instance();
        if (!raptureTextModule->MacroEncoder.EncoderError.IsEmpty)
        {
            ImGui.SameLine();
            ImGui.Text(raptureTextModule->MacroEncoder.EncoderError.ToString()); // TODO: EncoderError doesn't clear
        }

        ImGui.SameLine();
        ImGui.SetNextItemWidth(90 * ImGuiHelpers.GlobalScale);
        var languageName = this.language.ToString();
        using var dropdown = ImRaii.Combo("##Language"u8, languageName);
        if (dropdown)
        {
            var values = Enum.GetValues<ClientLanguage>().OrderBy(lang => lang.ToString());
            foreach (var value in values)
            {
                if (ImGui.Selectable(value.ToString(), value == this.language))
                {
                    this.language = value;
                    this.UpdateInputString();
                }
            }
        }
    }

    private void DrawAddFromSheetPopup()
    {
        using var popup = ImRaii.Popup("AddFromSheetPopup"u8);
        if (!popup) return;

        var dataManager = Service<DataManager>.Get();

        this.validImportSheetNamesTask ??= Task.Run(() =>
        {
            this.validImportSheetNames = dataManager.Excel.SheetNames.Where(sheetName =>
            {
                try
                {
                    var headerFile = dataManager.GameData.GetFile<ExcelHeaderFile>($"exd/{sheetName}.exh");
                    if (headerFile == null || headerFile.Header.Variant != ExcelVariant.Default)
                        return false;

                    var sheet = dataManager.Excel.GetSheet<RawRow>(Language.English, sheetName);
                    return sheet.Columns.Any(col => col.Type == ExcelColumnDataType.String);
                }
                catch
                {
                    return false;
                }
            }).OrderBy(sheetName => sheetName, StringComparer.InvariantCulture).ToArray();
        });

        if (this.validImportSheetNames == null)
        {
            ImGui.Text("正在加载表格..."u8);
            return;
        }

        var sheetChanged = ImGui.Combo("表名", ref this.importSelectedSheetName, this.validImportSheetNames);

        try
        {
            var sheet = dataManager.Excel.GetSheet<RawRow>(this.language?.ToLumina() ?? Language.English, this.validImportSheetNames[this.importSelectedSheetName]);
            var minRowId = (int)sheet.FirstOrDefault().RowId;
            var maxRowId = (int)sheet.LastOrDefault().RowId;

            var rowIdChanged = ImGui.InputInt("行 ID"u8, ref this.importRowId, 1, 10);

            ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);
            ImGui.Text($"（范围：{minRowId} - {maxRowId}）");

            if (sheetChanged || rowIdChanged)
            {
                if (sheetChanged || this.importRowId < minRowId)
                    this.importRowId = minRowId;

                if (this.importRowId > maxRowId)
                    this.importRowId = maxRowId;
            }

            if (!sheet.TryGetRow((uint)this.importRowId, out var row))
            {
                ImGui.TextColored(new Vector4(1, 0, 0, 1), "未找到该行"u8);
                return;
            }

            ImGui.Text("选择要添加的字符串："u8);

            using var table = ImRaii.Table("StringSelectionTable"u8, 2, ImGuiTableFlags.Borders | ImGuiTableFlags.NoSavedSettings);
            if (!table) return;

            ImGui.TableSetupColumn("列"u8, ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("值"u8, ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            for (var i = 0; i < sheet.Columns.Count; i++)
            {
                var column = sheet.Columns[i];
                if (column.Type != ExcelColumnDataType.String)
                    continue;

                var value = row.ReadStringColumn(i);
                if (value.IsEmpty)
                    continue;

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text(i.ToString());

                ImGui.TableNextColumn();
                if (ImGui.Selectable($"{value.ToMacroString().Truncate(100)}###Column{i}"))
                {
                    foreach (var payload in value)
                    {
                        switch (payload.Type)
                        {
                            case ReadOnlySePayloadType.Text:
                                this.entries.Add(new(TextEntryType.String, Encoding.UTF8.GetString(payload.Body.Span)));
                                break;

                            case ReadOnlySePayloadType.Macro:
                                this.entries.Add(new(TextEntryType.Macro, payload.ToString()));
                                break;
                        }
                    }

                    this.UpdateInputString();
                    ImGui.CloseCurrentPopup();
                }
            }
        }
        catch (Exception e)
        {
            ImGui.Text(e.Message);
        }
    }

    private void DrawInputs()
    {
        using var child = ImRaii.Child("Inputs"u8, new Vector2(this.inputsWidth, -1));
        if (!child) return;

        using var table = ImRaii.Table("StringMakerTable"u8, 3, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY | ImGuiTableFlags.NoSavedSettings);
        if (!table) return;

        ImGui.TableSetupColumn("类型"u8, ImGuiTableColumnFlags.WidthFixed, 100);
        ImGui.TableSetupColumn("文本"u8, ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("操作"u8, ImGuiTableColumnFlags.WidthFixed, 80);
        ImGui.TableSetupScrollFreeze(3, 1);
        ImGui.TableHeadersRow();

        var arrowUpButtonSize = this.GetIconButtonSize(FontAwesomeIcon.ArrowUp);
        var arrowDownButtonSize = this.GetIconButtonSize(FontAwesomeIcon.ArrowDown);

        var entryToRemove = -1;
        var entryToMoveUp = -1;
        var entryToMoveDown = -1;
        var updateString = false;

        for (var i = 0; i < this.entries.Count; i++)
        {
            var key = $"##Entry{i}";
            var entry = this.entries[i];

            ImGui.TableNextRow();

            ImGui.TableNextColumn(); // Type
            var type = (int)entry.Type;
            ImGui.SetNextItemWidth(-1);
            if (ImGui.Combo($"##Type{i}", ref type, TextEntryTypeOptions))
            {
                entry.Type = (TextEntryType)type;
                updateString |= true;
            }

            ImGui.TableNextColumn(); // Text
            var message = entry.Message;
            ImGui.SetNextItemWidth(-1);
            if (ImGui.InputText($"##{i}_Message", ref message, 2048))
            {
                entry.Message = message;
                updateString |= true;
            }

            ImGui.TableNextColumn(); // Actions

            if (i > 0)
            {
                if (this.IconButton(key + "_Up", FontAwesomeIcon.ArrowUp, "上移"))
                {
                    entryToMoveUp = i;
                }
            }
            else
            {
                ImGui.Dummy(arrowUpButtonSize);
            }

            ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);

            if (i < this.entries.Count - 1)
            {
                if (this.IconButton(key + "_Down", FontAwesomeIcon.ArrowDown, "下移"))
                {
                    entryToMoveDown = i;
                }
            }
            else
            {
                ImGui.Dummy(arrowDownButtonSize);
            }

            ImGui.SameLine(0, ImGui.GetStyle().ItemInnerSpacing.X);

            if (ImGui.IsKeyDown(ImGuiKey.LeftShift) || ImGui.IsKeyDown(ImGuiKey.RightShift))
            {
                if (this.IconButton(key + "_Delete", FontAwesomeIcon.Trash, "删除"))
                {
                    entryToRemove = i;
                }
            }
            else
            {
                this.IconButton(
                    key + "_Delete",
                    FontAwesomeIcon.Trash,
                    "按住 Shift 删除",
                    disabled: true);
            }
        }

        table.Dispose();

        if (entryToMoveUp != -1)
        {
            var removedItem = this.entries[entryToMoveUp];
            this.entries.RemoveAt(entryToMoveUp);
            this.entries.Insert(entryToMoveUp - 1, removedItem);
            updateString |= true;
        }

        if (entryToMoveDown != -1)
        {
            var removedItem = this.entries[entryToMoveDown];
            this.entries.RemoveAt(entryToMoveDown);
            this.entries.Insert(entryToMoveDown + 1, removedItem);
            updateString |= true;
        }

        if (entryToRemove != -1)
        {
            this.entries.RemoveAt(entryToRemove);
            updateString |= true;
        }

        if (updateString)
        {
            this.UpdateInputString();
        }
    }

    private void UpdateInputString(bool resetLocalParameters = true)
    {
        using var rssb = new RentedSeStringBuilder();

        foreach (var entry in this.entries)
        {
            switch (entry.Type)
            {
                case TextEntryType.String:
                    rssb.Builder.Append(entry.Message);
                    break;

                case TextEntryType.Macro:
                case TextEntryType.Fixed:
                    rssb.Builder.AppendMacroString(entry.Message);
                    break;
            }
        }

        this.input = rssb.Builder.ToReadOnlySeString();

        if (resetLocalParameters)
            this.localParameters = null;
    }

    private void DrawPreview(ReadOnlySeString str)
    {
        using var nodeColor = ImRaii.PushColor(ImGuiCol.Text, 0xFF00FF00);
        using var node = ImRaii.TreeNode("预览"u8, ImGuiTreeNodeFlags.DefaultOpen);
        nodeColor.Pop();
        if (!node) return;

        ImGui.Dummy(new Vector2(0, ImGui.GetTextLineHeight()));
        ImGui.SameLine(0, 0);
        ImGuiHelpers.SeStringWrapped(str);
    }

    private void DrawParameters()
    {
        using var nodeColor = ImRaii.PushColor(ImGuiCol.Text, 0xFF00FF00);
        using var node = ImRaii.TreeNode("参数"u8, ImGuiTreeNodeFlags.DefaultOpen);
        nodeColor.Pop();
        if (!node) return;

        for (var i = 0; i < this.localParameters!.Length; i++)
        {
            if (this.localParameters[i].IsString)
            {
                var str = this.localParameters[i].StringValue.ExtractText();
                if (ImGui.InputText($"lstr({i + 1})", ref str, 255))
                {
                    this.localParameters[i] = new(str);
                }
            }
            else
            {
                var num = (int)this.localParameters[i].UIntValue;
                if (ImGui.InputInt($"lnum({i + 1})", ref num))
                {
                    this.localParameters[i] = new((uint)num);
                }
            }
        }
    }

    private void DrawPayloads(ReadOnlySeString evaluated)
    {
        using (var nodeColor = ImRaii.PushColor(ImGuiCol.Text, 0xFF00FF00))
        using (var node = ImRaii.TreeNode("载荷"u8, ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth))
        {
            nodeColor.Pop();
            if (node) this.DrawSeString("payloads", this.input.AsSpan(), treeNodeFlags: ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth);
        }

        if (this.input.Equals(evaluated))
            return;

        using (var nodeColor = ImRaii.PushColor(ImGuiCol.Text, 0xFF00FF00))
        using (var node = ImRaii.TreeNode("载荷（已求值）"u8, ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth))
        {
            nodeColor.Pop();
            if (node) this.DrawSeString("payloads-evaluated", evaluated.AsSpan(), treeNodeFlags: ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth);
        }
    }

    private void DrawSeString(string id, ReadOnlySeStringSpan rosss, bool asTreeNode = false, bool renderSeString = false, int depth = 0, ImGuiTreeNodeFlags treeNodeFlags = ImGuiTreeNodeFlags.None)
    {
        using var seStringId = ImRaii.PushId(id);

        if (rosss.PayloadCount == 0)
        {
            ImGui.Dummy(Vector2.Zero);
            return;
        }

        using var node = asTreeNode ? this.SeStringTreeNode(id, rosss) : default;
        if (asTreeNode && !node) return;

        if (!asTreeNode && renderSeString)
        {
            ImGuiHelpers.SeStringWrapped(rosss, new()
            {
                ForceEdgeColor = true,
            });
        }

        var payloadIdx = -1;
        foreach (var payload in rosss)
        {
            payloadIdx++;
            using var payloadId = ImRaii.PushId(payloadIdx);

            var preview = payload.Type.ToString();
            if (payload.Type == ReadOnlySePayloadType.Macro)
                preview += $": {payload.MacroCode}";

            using var nodeColor = ImRaii.PushColor(ImGuiCol.Text, 0xFF00FFFF);
            using var payloadNode = ImRaii.TreeNode($"[{payloadIdx}] {preview}", ImGuiTreeNodeFlags.DefaultOpen | ImGuiTreeNodeFlags.SpanAvailWidth);
            nodeColor.Pop();
            if (!payloadNode) continue;

            using var table = ImRaii.Table($"##Payload{payloadIdx}Table", 2);
            if (!table) return;

            ImGui.TableSetupColumn("标签"u8, ImGuiTableColumnFlags.WidthFixed, 120);
            ImGui.TableSetupColumn("树"u8, ImGuiTableColumnFlags.WidthStretch);

            ImGui.TableNextRow();
            ImGui.TableNextColumn();
            ImGui.Text(payload.Type == ReadOnlySePayloadType.Text ? "Text" : "ToString()");
            ImGui.TableNextColumn();
            var text = payload.ToString();
            WidgetUtil.DrawCopyableText($"\"{text}\"", text);

            if (payload.Type != ReadOnlySePayloadType.Macro)
                continue;

            if (payload.ExpressionCount > 0)
            {
                var exprIdx = 0;
                uint? subType = null;
                uint? fixedType = null;

                if (payload.MacroCode == MacroCode.Link && payload.TryGetExpression(out var linkExpr1) && linkExpr1.TryGetUInt(out var linkExpr1Val))
                {
                    subType = linkExpr1Val;
                }
                else if (payload.MacroCode == MacroCode.Fixed && payload.TryGetExpression(out var fixedTypeExpr, out var linkExpr2) && fixedTypeExpr.TryGetUInt(out var fixedTypeVal) && linkExpr2.TryGetUInt(out var linkExpr2Val))
                {
                    subType = linkExpr2Val;
                    fixedType = fixedTypeVal;
                }

                foreach (var expr in payload)
                {
                    using var exprId = ImRaii.PushId(exprIdx);

                    this.DrawExpression(payload.MacroCode, subType, fixedType, exprIdx++, expr);
                }
            }
        }
    }

    private unsafe void DrawExpression(MacroCode macroCode, uint? subType, uint? fixedType, int exprIdx, ReadOnlySeExpressionSpan expr)
    {
        ImGui.TableNextRow();

        ImGui.TableNextColumn();
        var expressionName = this.GetExpressionName(macroCode, subType, exprIdx, expr);
        ImGui.Text($"[{exprIdx}] " + (string.IsNullOrEmpty(expressionName) ? $"表达式 {exprIdx}" : expressionName));

        ImGui.TableNextColumn();

        if (expr.Body.IsEmpty)
        {
            ImGui.Text("(?)"u8);
            return;
        }

        if (expr.TryGetUInt(out var u32))
        {
            if (macroCode is MacroCode.Icon or MacroCode.Icon2 && exprIdx == 0)
            {
                var iconId = u32;

                if (macroCode == MacroCode.Icon2)
                {
                    var iconMapping = RaptureAtkModule.Instance()->AtkFontManager.Icon2RemapTable;
                    for (var i = 0; i < 30; i++)
                    {
                        if (iconMapping[i].IconId == iconId)
                        {
                            iconId = iconMapping[i].RemappedIconId;
                            break;
                        }
                    }
                }

                using var rssb = new RentedSeStringBuilder();
                rssb.Builder.AppendIcon(iconId);
                ImGuiHelpers.SeStringWrapped(rssb.Builder.ToArray());

                ImGui.SameLine();
            }

            WidgetUtil.DrawCopyableText(u32.ToString());
            ImGui.SameLine();
            WidgetUtil.DrawCopyableText($"0x{u32:X}");

            if (macroCode == MacroCode.Link && exprIdx == 0)
            {
                var name = subType != null && (LinkMacroPayloadType)subType == DalamudLinkType
                    ? "Dalamud"
                    : Enum.GetName((LinkMacroPayloadType)u32);

                if (!string.IsNullOrEmpty(name))
                {
                    ImGui.SameLine();
                    ImGui.Text(name);
                }
            }

            if (macroCode is MacroCode.JaNoun or MacroCode.EnNoun or MacroCode.DeNoun or MacroCode.FrNoun && exprIdx == 1)
            {
                var macroLanguage = macroCode switch
                {
                    MacroCode.JaNoun => ClientLanguage.Japanese,
                    MacroCode.DeNoun => ClientLanguage.German,
                    MacroCode.FrNoun => ClientLanguage.French,
                    _ => ClientLanguage.English,
                };
                var articleTypeEnumType = macroLanguage switch
                {
                    ClientLanguage.Japanese => typeof(JapaneseArticleType),
                    ClientLanguage.German => typeof(GermanArticleType),
                    ClientLanguage.French => typeof(FrenchArticleType),
                    _ => typeof(EnglishArticleType),
                };
                ImGui.SameLine();
                ImGui.Text(Enum.GetName(articleTypeEnumType, u32));
            }

            if (macroCode is MacroCode.DeNoun && exprIdx == 4 && u32 is >= 0 and <= 4)
            {
                ImGui.SameLine();
                ImGui.Text(NounProcessorWidget.GermanCaseDisplayNames[u32]);
            }

            if (macroCode is MacroCode.Fixed && subType != null && fixedType != null && fixedType is 100 or 200 && subType == 5 && exprIdx == 2)
            {
                ImGui.SameLine();
                if (ImGui.SmallButton("播放"u8))
                {
                    UIGlobals.PlayChatSoundEffect(u32 + 1);
                }
            }

            if (macroCode is MacroCode.Link && subType != null && exprIdx == 1)
            {
                var dataManager = Service<DataManager>.Get();

                switch ((LinkMacroPayloadType)subType)
                {
                    case LinkMacroPayloadType.Item when dataManager.GetExcelSheet<Item>(this.language).TryGetRow(u32, out var itemRow):
                        ImGui.SameLine();
                        ImGui.Text(itemRow.Name.ExtractText());
                        break;

                    case LinkMacroPayloadType.Quest when dataManager.GetExcelSheet<Quest>(this.language).TryGetRow(u32, out var questRow):
                        ImGui.SameLine();
                        ImGui.Text(questRow.Name.ExtractText());
                        break;

                    case LinkMacroPayloadType.Achievement when dataManager.GetExcelSheet<Achievement>(this.language).TryGetRow(u32, out var achievementRow):
                        ImGui.SameLine();
                        ImGui.Text(achievementRow.Name.ExtractText());
                        break;

                    case LinkMacroPayloadType.HowTo when dataManager.GetExcelSheet<HowTo>(this.language).TryGetRow(u32, out var howToRow):
                        ImGui.SameLine();
                        ImGui.Text(howToRow.Name.ExtractText());
                        break;

                    case LinkMacroPayloadType.Status when dataManager.GetExcelSheet<Status>(this.language).TryGetRow(u32, out var statusRow):
                        ImGui.SameLine();
                        ImGui.Text(statusRow.Name.ExtractText());
                        break;

                    case LinkMacroPayloadType.AkatsukiNote when
                        dataManager.GetSubrowExcelSheet<AkatsukiNote>(this.language).TryGetSubrow(u32, 0, out var akatsukiNoteRow) &&
                        akatsukiNoteRow.ListName.ValueNullable is { } akatsukiNoteStringRow:
                        ImGui.SameLine();
                        ImGui.Text(akatsukiNoteStringRow.Text.ExtractText());
                        break;
                }
            }

            return;
        }

        if (expr.TryGetString(out var s))
        {
            this.DrawSeString("Preview", s, treeNodeFlags: ImGuiTreeNodeFlags.DefaultOpen);
            return;
        }

        if (expr.TryGetPlaceholderExpression(out var exprType))
        {
            if (((ExpressionType)exprType).GetNativeName() is { } nativeName)
            {
                ImGui.Text(nativeName);
                return;
            }

            ImGui.Text($"?x{exprType:X02}");
            return;
        }

        if (expr.TryGetParameterExpression(out exprType, out var e1))
        {
            if (((ExpressionType)exprType).GetNativeName() is { } nativeName)
            {
                ImGui.Text($"{nativeName}({e1.ToString()})");
                return;
            }

            throw new InvalidOperationException("必须为所有一元表达式定义原生名称。");
        }

        if (expr.TryGetBinaryExpression(out exprType, out e1, out var e2))
        {
            if (((ExpressionType)exprType).GetNativeName() is { } nativeName)
            {
                ImGui.Text($"{e1.ToString()} {nativeName} {e2.ToString()}");
                return;
            }

            throw new InvalidOperationException("必须为所有二元表达式定义原生名称。");
        }

        var sb = new StringBuilder();
        sb.EnsureCapacity(1 + 3 * expr.Body.Length);
        sb.Append($"({expr.Body[0]:X02}");
        for (var i = 1; i < expr.Body.Length; i++)
            sb.Append($" {expr.Body[i]:X02}");
        sb.Append(')');
        ImGui.Text(sb.ToString());
    }

    private string GetExpressionName(MacroCode macroCode, uint? subType, int idx, ReadOnlySeExpressionSpan expr)
    {
        if (this.expressionNames.TryGetValue(macroCode, out var names) && idx < names.Length)
            return names[idx];

        if (macroCode == MacroCode.Switch)
            return $"分支 {idx - 1}";

        if (macroCode == MacroCode.Link && subType != null && this.linkExpressionNames.TryGetValue((LinkMacroPayloadType)subType, out var linkNames) && idx - 1 < linkNames.Length)
            return linkNames[idx - 1];

        if (macroCode == MacroCode.Fixed && subType != null && this.fixedExpressionNames.TryGetValue((uint)subType, out var fixedNames) && idx < fixedNames.Length)
            return fixedNames[idx];

        if (macroCode == MacroCode.Link && idx == 4)
            return "复制字符串";

        return string.Empty;
    }

    private SeStringParameter[] GetLocalParameters(ReadOnlySeStringSpan rosss, Dictionary<uint, SeStringParameter>? parameters)
    {
        parameters ??= [];

        void ProcessString(ReadOnlySeStringSpan rosss)
        {
            foreach (var payload in rosss)
            {
                foreach (var expression in payload)
                {
                    ProcessExpression(expression);
                }
            }
        }

        void ProcessExpression(ReadOnlySeExpressionSpan expression)
        {
            if (expression.TryGetString(out var exprString))
            {
                ProcessString(exprString);
                return;
            }

            if (expression.TryGetBinaryExpression(out var expressionType, out var operand1, out var operand2))
            {
                ProcessExpression(operand1);
                ProcessExpression(operand2);
                return;
            }

            if (expression.TryGetParameterExpression(out expressionType, out var operand))
            {
                if (!operand.TryGetUInt(out var index))
                    return;

                if (parameters.ContainsKey(index))
                    return;

                if (expressionType == (int)ExpressionType.LocalNumber)
                {
                    parameters[index] = new SeStringParameter(0);
                }
                else if (expressionType == (int)ExpressionType.LocalString)
                {
                    parameters[index] = new SeStringParameter(string.Empty);
                }
            }
        }

        ProcessString(rosss);

        if (parameters.Count > 0)
        {
            var last = parameters.OrderBy(x => x.Key).Last();

            if (parameters.Count != last.Key)
            {
                // fill missing local parameter slots, so we can go off the array index in SeStringContext

                for (var i = 1u; i <= last.Key; i++)
                {
                    if (!parameters.ContainsKey(i))
                        parameters[i] = new SeStringParameter(0);
                }
            }
        }

        return parameters.OrderBy(x => x.Key).Select(x => x.Value).ToArray();
    }

    private ImRaii.TreeNodeDisposable SeStringTreeNode(string id, ReadOnlySeStringSpan previewText, uint color = 0xFF00FFFF, ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags.None)
    {
        using var titleColor = ImRaii.PushColor(ImGuiCol.Text, color);
        var node = ImRaii.TreeNode("##" + id, flags);
        ImGui.SameLine();
        ImGuiHelpers.SeStringWrapped(previewText, new()
        {
            ForceEdgeColor = true,
            WrapWidth = 9999,
        });
        return node;
    }

    private bool IconButton(string key, FontAwesomeIcon icon, string tooltip, Vector2 size = default, bool disabled = false, bool active = false)
    {
        using var iconFont = ImRaii.PushFont(UiBuilder.IconFont);
        if (!key.StartsWith("##")) key = "##" + key;

        var disposables = new List<IDisposable>();

        if (disabled)
        {
            disposables.Add(ImRaii.PushColor(ImGuiCol.Text, ImGui.GetStyle().Colors[(int)ImGuiCol.TextDisabled]));
            disposables.Add(ImRaii.PushColor(ImGuiCol.ButtonActive, ImGui.GetStyle().Colors[(int)ImGuiCol.Button]));
            disposables.Add(ImRaii.PushColor(ImGuiCol.ButtonHovered, ImGui.GetStyle().Colors[(int)ImGuiCol.Button]));
        }
        else if (active)
        {
            disposables.Add(ImRaii.PushColor(ImGuiCol.Button, ImGui.GetStyle().Colors[(int)ImGuiCol.ButtonActive]));
        }

        var pressed = ImGui.Button(icon.ToIconString() + key, size);

        foreach (var disposable in disposables)
            disposable.Dispose();

        iconFont?.Dispose();

        if (ImGui.IsItemHovered())
        {
            ImGui.BeginTooltip();
            ImGui.Text(tooltip);
            ImGui.EndTooltip();
        }

        return pressed;
    }

    private Vector2 GetIconButtonSize(FontAwesomeIcon icon)
    {
        using var iconFont = ImRaii.PushFont(UiBuilder.IconFont);
        return ImGui.CalcTextSize(icon.ToIconString()) + ImGui.GetStyle().FramePadding * 2;
    }

    private class TextEntry(TextEntryType type, string text)
    {
        public string Message { get; set; } = text;

        public TextEntryType Type { get; set; } = type;
    }
}
