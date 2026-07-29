using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

using Dalamud.Bindings.ImGui;
using Dalamud.Data;
using Dalamud.Game;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Components;
using Dalamud.Interface.Textures.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Memory;

using Lumina.Data.Files;
using Lumina.Data.Parsing.Uld;

using static Lumina.Data.Parsing.Uld.Keyframes;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Displays the full data of the selected ULD element.
/// </summary>
internal class UldWidget : IDataWindowWidget
{
    private const string UldBaseBath = "ui/uld/";

    // ULD styles can be hardcoded for now as they don't add new ones regularly. Can later try and find where to load these from in the game EXE.
    private static readonly string[] ThemeDisplayNames = ["深色", "浅色", "经典 FF", "透明蓝", "透明白", "透明绿"];

    // 48 8D 15 ?? ?? ?? ?? is the part of the signatures that contain the string location offset
    // 48 = 64 bit register prefix
    // 8D = LEA instruction
    // 15 = register to store offset in (RDX in this case as Component::GUI::AtkUnitBase_LoadUldByName name component is loaded from RDX)
    // ?? ?? ?? ?? = offset to string location
    private static readonly (string Sig, nint Offset)[] UldSigLocations =
    [
        ("45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8B CF 48 8B 5C 24 30 48 83 C4 20 5F E9 ?? ?? ?? ??", 6),
        ("48 8D 15 ?? ?? ?? ?? 45 33 C0 48 8B CE 48 8B 5C ?? ?? 48 8B 74 ?? ?? 48 83 C4 20 5F E9 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 45 33 C0 48 8B CB 48 83 C4 20 5B E9 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? 45 33 C0 E8 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? 45 33 C0 E9 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 45 33 C0 48 8B CB E8 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 41 B0 01 E9 ?? ?? ?? ??", 3),
        ("48 8D 15 ?? ?? ?? ?? 45 33 C0 E9 ?? ?? ?? ??", 3)
    ];

    private DataManager dataManager;
    private CancellationTokenSource? cts;
    private Task<string[]>? uldNamesTask;

    private int selectedUld;
    private int selectedFrameData;
    private int selectedTimeline;
    private int selectedParts;
    private int selectedTheme;
    private Task<UldFile>? selectedUldFileTask;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["uld"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "ULD 数据";

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.dataManager ??= Service<DataManager>.Get();

        this.cts?.Cancel();
        ClearTask(ref this.uldNamesTask);
        this.uldNamesTask = null;
        this.cts = new();

        this.Ready = true;
        this.selectedUld = this.selectedFrameData = this.selectedTimeline = this.selectedParts = 0;
        this.selectedTheme = 0;
        this.selectedUldFileTask = null;
    }

    /// <inheritdoc/>
    public void Draw()
    {
        string[] uldNames;
        var ct = (this.cts ??= new()).Token;
        switch (this.uldNamesTask ??= ParseUldStringsAsync(ct))
        {
            case { IsCompletedSuccessfully: true } t:
                uldNames = t.Result;
                break;
            case { Exception: { } loadException }:
                ImGui.TextColoredWrapped(ImGuiColors.ErrorForeground, loadException.ToString());
                return;
            case { IsCanceled: true }:
                ClearTask(ref this.uldNamesTask);
                goto default;
            default:
                ImGui.Text("加载中..."u8);
                return;
        }

        var selectedUldPrev = this.selectedUld;
        ImGui.Combo("##selectUld", ref this.selectedUld, uldNames);
        ImGui.SameLine();
        if (ImGuiComponents.IconButton("selectUldLeft", FontAwesomeIcon.AngleLeft))
            this.selectedUld = ((this.selectedUld + uldNames.Length) - 1) % uldNames.Length;
        ImGui.SameLine();
        if (ImGuiComponents.IconButton("selectUldRight", FontAwesomeIcon.AngleRight))
            this.selectedUld = (this.selectedUld + 1) % uldNames.Length;
        ImGui.SameLine();
        ImGui.Text("选择 ULD 文件"u8);
        if (selectedUldPrev != this.selectedUld)
        {
            // reset selected parts when changing ULD
            this.selectedFrameData = this.selectedTimeline = this.selectedParts = 0;
            ClearTask(ref this.selectedUldFileTask);
        }

        ImGui.Combo("##selectTheme", ref this.selectedTheme, ThemeDisplayNames);
        ImGui.SameLine();
        if (ImGuiComponents.IconButton("selectThemeLeft", FontAwesomeIcon.AngleLeft))
            this.selectedTheme = ((this.selectedTheme + ThemeDisplayNames.Length) - 1) % ThemeDisplayNames.Length;
        ImGui.SameLine();
        if (ImGuiComponents.IconButton("selectThemeRight", FontAwesomeIcon.AngleRight))
            this.selectedTheme = (this.selectedTheme + 1) % ThemeDisplayNames.Length;
        ImGui.SameLine();
        ImGui.Text("选择主题"u8);

        var dataManager = Service<DataManager>.Get();
        var textureManager = Service<TextureManager>.Get();

        UldFile uld;
        switch (this.selectedUldFileTask ??=
                    dataManager.GetFileAsync<UldFile>($"ui/uld/{uldNames[this.selectedUld]}.uld", ct))
        {
            case { IsCompletedSuccessfully: true }:
                uld = this.selectedUldFileTask.Result;
                break;
            case { Exception: { } loadException }:
                ImGui.TextColoredWrapped(
                    ImGuiColors.ErrorForeground,
                    $"无法加载 ULD 文件。\n{loadException}");
                return;
            case { IsCanceled: true }:
                this.selectedUldFileTask = null;
                goto default;
            default:
                ImGui.Text("加载中..."u8);
                return;
        }

        if (ImGui.CollapsingHeader("纹理条目"u8))
        {
            if (ForceNullable(uld.AssetData) is null)
            {
                ImGui.TextColoredWrapped(
                    ImGuiColors.ErrorForeground,
                    $"错误：{nameof(UldFile.AssetData)} 尚未填充。");
            }
            else
            {
                using var table = ImRaii.Table("##uldTextureEntries"u8, 3, ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders);
                if (table.Success)
                {
                    ImGui.TableSetupColumn("ID"u8, ImGuiTableColumnFlags.WidthFixed, ImGui.CalcTextSize("000000"u8).X);
                    ImGui.TableSetupColumn("路径"u8, ImGuiTableColumnFlags.WidthStretch);
                    ImGui.TableSetupColumn("操作"u8, ImGuiTableColumnFlags.WidthFixed, ImGui.CalcTextSize("Preview___"u8).X);
                    ImGui.TableHeadersRow();

                    foreach (var textureEntry in uld.AssetData)
                        this.DrawTextureEntry(textureEntry, textureManager);
                }
            }
        }

        if (ImGui.CollapsingHeader("时间轴##TimelineCollapsingHeader"u8))
        {
            if (ForceNullable(uld.Timelines) is null)
            {
                ImGui.TextColoredWrapped(
                    ImGuiColors.ErrorForeground,
                    $"错误：{nameof(UldFile.Timelines)} 尚未填充。");
            }
            else if (uld.Timelines.Length == 0)
            {
                ImGui.Text("没有可用条目。"u8);
            }
            else
            {
                ImGui.SliderInt("时间轴##TimelineSlider"u8, ref this.selectedTimeline, 0, uld.Timelines.Length - 1);
                this.DrawTimelines(uld.Timelines[this.selectedTimeline]);
            }
        }

        if (ImGui.CollapsingHeader("部件##PartsCollapsingHeader"u8))
        {
            if (ForceNullable(uld.Parts) is null)
            {
                ImGui.TextColoredWrapped(
                    ImGuiColors.ErrorForeground,
                    $"错误：{nameof(UldFile.Parts)} 尚未填充。");
            }
            else if (uld.Parts.Length == 0)
            {
                ImGui.Text("没有可用条目。"u8);
            }
            else
            {
                ImGui.SliderInt("部件##PartsSlider"u8, ref this.selectedParts, 0, uld.Parts.Length - 1);
                this.DrawParts(uld.Parts[this.selectedParts], uld.AssetData, textureManager);
            }
        }

        return;
        static T? ForceNullable<T>(T smth) => smth;
    }

    /// <summary>
    /// Gets all known ULD locations in the game based on a few signatures.
    /// </summary>
    /// <returns>Uld locations.</returns>
    private static Task<string[]> ParseUldStringsAsync(CancellationToken cancellationToken) =>
        Task.Run(
            () =>
            {
                // game contains possibly around 1500 ULD files but current sigs only find less than that due to how they are used
                var locations = new List<string>(1000);
                var sigScanner = new SigScanner(Process.GetCurrentProcess().MainModule!);
                foreach (var (uldSig, strLocOffset) in UldSigLocations)
                {
                    foreach (var ea in sigScanner.ScanAllText(uldSig, cancellationToken))
                    {
                        var strLoc = ea + strLocOffset;
                        // offset instruction is always 4 bytes so need to read as uint and cast to nint for offset calculation
                        var offset = (nint)MemoryHelper.Read<uint>(strLoc);
                        // strings are always stored as c strings and relative from end of offset instruction
                        var str = MemoryHelper.ReadStringNullTerminated(strLoc + 4 + offset);
                        locations.Add(str);
                    }
                }

                return locations.Distinct().Order().ToArray();
            },
            cancellationToken);

    private static void ClearTask<T>(ref Task<T>? task)
    {
        try
        {
            task?.Wait();
        }
        catch
        {
            // ignore
        }

        task = null;
    }

    private static string GetStringNullTerminated(ReadOnlySpan<char> text)
    {
        var index = text.IndexOf((char)0);
        return index == -1 ? new(text) : new(text[..index]);
    }

    private string ToThemedPath(string path) =>
        UldBaseBath + (this.selectedTheme > 0 ? $"img{this.selectedTheme:D2}/" : string.Empty) + path[UldBaseBath.Length..];

    private void DrawTextureEntry(UldRoot.TextureEntry textureEntry, TextureManager textureManager)
    {
        var path = GetStringNullTerminated(textureEntry.Path);
        ImGui.TableNextColumn();
        ImGui.Text(textureEntry.Id.ToString());

        ImGui.TableNextColumn();
        this.TextColumnCopiable(path, false, false);

        ImGui.TableNextColumn();
        if (string.IsNullOrWhiteSpace(path))
            return;

        ImGui.Text("预览"u8);

        if (ImGui.IsItemHovered())
        {
            using var tooltip = ImRaii.Tooltip();

            var texturePath = GetStringNullTerminated(textureEntry.Path);
            ImGui.Text($"基础路径 {texturePath}：");
            if (textureManager.Shared.GetFromGame(texturePath).TryGetWrap(out var wrap, out var e))
                ImGui.Image(wrap.Handle, wrap.Size);
            else if (e is not null)
                ImGui.Text(e.ToString());

            if (this.selectedTheme != 0 && (textureEntry.ThemeSupportBitmask & (1 << (this.selectedTheme - 1))) != 0)
            {
                var texturePathThemed = this.ToThemedPath(texturePath);
                if (this.dataManager.FileExists(texturePathThemed))
                {
                    ImGui.Text($"主题路径 {texturePathThemed}：");
                    if (textureManager.Shared.GetFromGame(texturePathThemed).TryGetWrap(out wrap, out e))
                        ImGui.Image(wrap.Handle, wrap.Size);
                    else if (e is not null)
                        ImGui.Text(e.ToString());
                }
            }
        }
    }

    private void DrawTimelines(UldRoot.Timeline timeline)
    {
        ImGui.SliderInt("帧数据"u8, ref this.selectedFrameData, 0, timeline.FrameData.Length - 1);
        var frameData = timeline.FrameData[this.selectedFrameData];
        ImGui.Text($"帧信息：{frameData.StartFrame} -> {frameData.EndFrame}");

        using var indent = ImRaii.PushIndent();
        foreach (var frameDataKeyGroup in frameData.KeyGroups)
        {
            ImGui.Text($"{frameDataKeyGroup.Usage:G} {frameDataKeyGroup.Type:G}");
            foreach (var keyframe in frameDataKeyGroup.Frames)
                this.DrawTimelineKeyGroupFrame(keyframe);
        }
    }

    private void DrawTimelineKeyGroupFrame(IKeyframe frame)
    {
        switch (frame)
        {
            case BaseKeyframeData baseKeyframeData:
                ImGui.Text($"时间：{baseKeyframeData.Time} | 插值：{baseKeyframeData.Interpolation} | 加速度：{baseKeyframeData.Acceleration} | 减速度：{baseKeyframeData.Deceleration}");
                break;
            case Float1Keyframe float1Keyframe:
                this.DrawTimelineKeyGroupFrame(float1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{float1Keyframe.Value}");
                break;
            case Float2Keyframe float2Keyframe:
                this.DrawTimelineKeyGroupFrame(float2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{float2Keyframe.Value[0]} | 值 2：{float2Keyframe.Value[1]}");
                break;
            case Float3Keyframe float3Keyframe:
                this.DrawTimelineKeyGroupFrame(float3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{float3Keyframe.Value[0]} | 值 2：{float3Keyframe.Value[1]} | 值 3：{float3Keyframe.Value[2]}");
                break;
            case SByte1Keyframe sbyte1Keyframe:
                this.DrawTimelineKeyGroupFrame(sbyte1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{sbyte1Keyframe.Value}");
                break;
            case SByte2Keyframe sbyte2Keyframe:
                this.DrawTimelineKeyGroupFrame(sbyte2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{sbyte2Keyframe.Value[0]} | 值 2：{sbyte2Keyframe.Value[1]}");
                break;
            case SByte3Keyframe sbyte3Keyframe:
                this.DrawTimelineKeyGroupFrame(sbyte3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{sbyte3Keyframe.Value[0]} | 值 2：{sbyte3Keyframe.Value[1]} | 值 3：{sbyte3Keyframe.Value[2]}");
                break;
            case Byte1Keyframe byte1Keyframe:
                this.DrawTimelineKeyGroupFrame(byte1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{byte1Keyframe.Value}");
                break;
            case Byte2Keyframe byte2Keyframe:
                this.DrawTimelineKeyGroupFrame(byte2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{byte2Keyframe.Value[0]} | 值 2：{byte2Keyframe.Value[1]}");
                break;
            case Byte3Keyframe byte3Keyframe:
                this.DrawTimelineKeyGroupFrame(byte3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{byte3Keyframe.Value[0]} | 值 2：{byte3Keyframe.Value[1]} | 值 3：{byte3Keyframe.Value[2]}");
                break;
            case Short1Keyframe short1Keyframe:
                this.DrawTimelineKeyGroupFrame(short1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{short1Keyframe.Value}");
                break;
            case Short2Keyframe short2Keyframe:
                this.DrawTimelineKeyGroupFrame(short2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{short2Keyframe.Value[0]} | 值 2：{short2Keyframe.Value[1]}");
                break;
            case Short3Keyframe short3Keyframe:
                this.DrawTimelineKeyGroupFrame(short3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{short3Keyframe.Value[0]} | 值 2：{short3Keyframe.Value[1]} | 值 3：{short3Keyframe.Value[2]}");
                break;
            case UShort1Keyframe ushort1Keyframe:
                this.DrawTimelineKeyGroupFrame(ushort1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{ushort1Keyframe.Value}");
                break;
            case UShort2Keyframe ushort2Keyframe:
                this.DrawTimelineKeyGroupFrame(ushort2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{ushort2Keyframe.Value[0]} | 值 2：{ushort2Keyframe.Value[1]}");
                break;
            case UShort3Keyframe ushort3Keyframe:
                this.DrawTimelineKeyGroupFrame(ushort3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{ushort3Keyframe.Value[0]} | 值 2：{ushort3Keyframe.Value[1]} | 值 3：{ushort3Keyframe.Value[2]}");
                break;
            case Int1Keyframe int1Keyframe:
                this.DrawTimelineKeyGroupFrame(int1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{int1Keyframe.Value}");
                break;
            case Int2Keyframe int2Keyframe:
                this.DrawTimelineKeyGroupFrame(int2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{int2Keyframe.Value[0]} | 值 2：{int2Keyframe.Value[1]}");
                break;
            case Int3Keyframe int3Keyframe:
                this.DrawTimelineKeyGroupFrame(int3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{int3Keyframe.Value[0]} | 值 2：{int3Keyframe.Value[1]} | 值 3：{int3Keyframe.Value[2]}");
                break;
            case UInt1Keyframe uint1Keyframe:
                this.DrawTimelineKeyGroupFrame(uint1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{uint1Keyframe.Value}");
                break;
            case UInt2Keyframe uint2Keyframe:
                this.DrawTimelineKeyGroupFrame(uint2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{uint2Keyframe.Value[0]} | 值 2：{uint2Keyframe.Value[1]}");
                break;
            case UInt3Keyframe uint3Keyframe:
                this.DrawTimelineKeyGroupFrame(uint3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{uint3Keyframe.Value[0]} | 值 2：{uint3Keyframe.Value[1]} | 值 3：{uint3Keyframe.Value[2]}");
                break;
            case Bool1Keyframe bool1Keyframe:
                this.DrawTimelineKeyGroupFrame(bool1Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值：{(bool1Keyframe.Value ? "是" : "否")}");
                break;
            case Bool2Keyframe bool2Keyframe:
                this.DrawTimelineKeyGroupFrame(bool2Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{(bool2Keyframe.Value[0] ? "是" : "否")} | 值 2：{(bool2Keyframe.Value[1] ? "是" : "否")}");
                break;
            case Bool3Keyframe bool3Keyframe:
                this.DrawTimelineKeyGroupFrame(bool3Keyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 值 1：{(bool3Keyframe.Value[0] ? "是" : "否")} | 值 2：{(bool3Keyframe.Value[1] ? "是" : "否")} | 值 3：{(bool3Keyframe.Value[2] ? "是" : "否")}");
                break;
            case ColorKeyframe colorKeyframe:
                this.DrawTimelineKeyGroupFrame(colorKeyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 加色：{colorKeyframe.AddRed} {colorKeyframe.AddGreen} {colorKeyframe.AddBlue} | 乘色：{colorKeyframe.MultiplyRed} {colorKeyframe.MultiplyGreen} {colorKeyframe.MultiplyBlue}");
                break;
            case LabelKeyframe labelKeyframe:
                this.DrawTimelineKeyGroupFrame(labelKeyframe.Keyframe);
                ImGui.SameLine(0, 0);
                ImGui.Text($" | 标签命令：{labelKeyframe.LabelCommand} | 跳转 ID：{labelKeyframe.JumpId} | 标签 ID：{labelKeyframe.LabelId}");
                break;
        }
    }

    private void DrawParts(UldRoot.PartsData partsData, UldRoot.TextureEntry[] textureEntries, TextureManager textureManager)
    {
        for (var index = 0; index < partsData.Parts.Length; index++)
        {
            ImGui.Text($"索引：{index}");
            var partsDataPart = partsData.Parts[index];
            ImGui.SameLine();

            char[]? path = null;
            foreach (var textureEntry in textureEntries)
            {
                if (textureEntry.Id != partsDataPart.TextureId)
                    continue;
                path = textureEntry.Path;
                break;
            }

            if (path is null)
            {
                ImGui.Text($"未找到 ID 为 {partsDataPart.TextureId} 的纹理");
                continue;
            }

            var texturePath = GetStringNullTerminated(path);
            if (string.IsNullOrWhiteSpace(texturePath))
            {
                ImGui.Text("纹理路径为空。"u8);
                continue;
            }

            var texturePathThemed = this.ToThemedPath(texturePath);
            if (textureManager.Shared.GetFromGame(texturePathThemed).TryGetWrap(out var wrap, out var e))
            {
                texturePath = texturePathThemed;
            }
            else
            {
                // try loading from default location if not found in selected style
                if (!textureManager.Shared.GetFromGame(texturePath).TryGetWrap(out wrap, out var e2))
                {
                    // neither the supposedly original path nor themed path had a file we could load.
                    if (e is not null && e2 is not null)
                    {
                        ImGui.Text($"{texturePathThemed}: {e}\n{texturePath}: {e2}");
                        continue;
                    }
                }
            }

            var partSize = new Vector2(partsDataPart.W, partsDataPart.H);
            if (wrap is null)
            {
                ImGuiHelpers.ScaledDummy(partSize);
            }
            else
            {
                var uv0 = new Vector2(partsDataPart.U, partsDataPart.V);
                var uv1 = uv0 + partSize;
                ImGui.Image(wrap.Handle, partSize * ImGuiHelpers.GlobalScale, uv0 / wrap.Size, uv1 / wrap.Size);
            }

            if (ImGui.IsItemClicked())
                ImGui.SetClipboardText(texturePath);

            if (ImGui.IsItemHovered())
            {
                using var tooltip = ImRaii.Tooltip();
                ImGui.Text("单击复制："u8);
                ImGui.Text(texturePath);
            }
        }
    }
}
