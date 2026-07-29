using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Text;

using Dalamud.Bindings.ImGui;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.Internal;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Utility.Raii;
using Dalamud.Plugin.Ipc.Internal;

using Newtonsoft.Json;

using Formatting = Newtonsoft.Json.Formatting;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying plugin data share modules.
/// </summary>
internal class DataShareWidget : IDataWindowWidget
{
    private const ImGuiTabItemFlags NoCloseButton = (ImGuiTabItemFlags)ImGuiTabItemFlagsPrivate.NoCloseButton;

    private readonly List<(string Name, byte[]? Data)> dataView = [];
    private int nextTab = -1;
    private IReadOnlyDictionary<string, CallGateChannel>? gates;
    private List<CallGateChannel>? gatesSorted;

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["datashare"];

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "数据共享与调用门";

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
        using var tabbar = ImRaii.TabBar("##tabbar"u8);
        if (!tabbar.Success)
            return;

        var d = true;
        using (var tabItem = ImRaii.TabItem("数据共享##tabbar-datashare"u8, ref d, NoCloseButton | (this.nextTab == 0 ? ImGuiTabItemFlags.SetSelected : 0)))
        {
            if (tabItem.Success)
                this.DrawDataShare();
        }

        using (var tabItem = ImRaii.TabItem("调用门##tabbar-callgate"u8, ref d, NoCloseButton | (this.nextTab == 1 ? ImGuiTabItemFlags.SetSelected : 0)))
        {
            if (tabItem.Success)
                this.DrawCallGate();
        }

        for (var i = 0; i < this.dataView.Count; i++)
        {
            using var idpush = ImRaii.PushId($"##tabbar-data-{i}");

            var (name, data) = this.dataView[i];
            d = true;

            using var tabitem = ImRaii.TabItem(name, ref d, this.nextTab == 2 + i ? ImGuiTabItemFlags.SetSelected : 0);

            if (!d)
                this.dataView.RemoveAt(i--);

            if (!tabitem.Success)
                continue;

            if (ImGui.Button("刷新"u8))
                data = null;

            if (data is null)
            {
                try
                {
                    var dataShare = Service<DataShare>.Get();
                    var data2 = dataShare.GetData<object>(name, new DataCachePluginId("DataShareWidget", Guid.Empty));
                    try
                    {
                        data = Encoding.UTF8.GetBytes(
                            JsonConvert.SerializeObject(
                                data2,
                                Formatting.Indented,
                                new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }));
                    }
                    finally
                    {
                        dataShare.RelinquishData(name, new DataCachePluginId("DataShareWidget", Guid.Empty));
                    }
                }
                catch (Exception e)
                {
                    data = Encoding.UTF8.GetBytes(e.ToString());
                }

                this.dataView[i] = (name, data);
            }

            ImGui.SameLine();
            if (ImGui.Button("复制"u8))
                ImGui.SetClipboardText(data);

            ImGui.InputTextMultiline("文本"u8, data, ImGui.GetContentRegionAvail(), ImGuiInputTextFlags.ReadOnly);
        }

        this.nextTab = -1;
    }

    private static string ReprMethod(MethodInfo? mi, bool withParams)
    {
        if (mi is null)
            return "-";

        var sb = new StringBuilder();
        sb.Append(ReprType(mi.DeclaringType))
          .Append("::")
          .Append(mi.Name);

        if (!withParams)
            return sb.ToString();

        sb.Append('(');
        var parfirst = true;
        foreach (var par in mi.GetParameters())
        {
            if (!parfirst)
                sb.Append(", ");
            else
                parfirst = false;

            sb.AppendLine()
              .Append('\t')
              .Append(ReprType(par.ParameterType))
              .Append(' ')
              .Append(par.Name);
        }

        if (!parfirst)
            sb.AppendLine();

        sb.Append(')');
        if (mi.ReturnType != typeof(void))
            sb.Append(" -> ").Append(ReprType(mi.ReturnType));

        return sb.ToString();

        static string WithoutGeneric(string s)
        {
            var i = s.IndexOf('`');
            return i != -1 ? s[..i] : s;
        }

        static string ReprType(Type? t) => t switch
            {
                null => "null",
                _ when t == typeof(string) => "string",
                _ when t == typeof(object) => "object",
                _ when t == typeof(void) => "void",
                _ when t == typeof(decimal) => "decimal",
                _ when t == typeof(bool) => "bool",
                _ when t == typeof(double) => "double",
                _ when t == typeof(float) => "float",
                _ when t == typeof(char) => "char",
                _ when t == typeof(ulong) => "ulong",
                _ when t == typeof(long) => "long",
                _ when t == typeof(uint) => "uint",
                _ when t == typeof(int) => "int",
                _ when t == typeof(ushort) => "ushort",
                _ when t == typeof(short) => "short",
                _ when t == typeof(byte) => "byte",
                _ when t == typeof(sbyte) => "sbyte",
                _ when t == typeof(nint) => "nint",
                _ when t == typeof(nuint) => "nuint",
                _ when t.IsArray && t.HasElementType => ReprType(t.GetElementType()) + "[]",
                _ when t.IsPointer && t.HasElementType => ReprType(t.GetElementType()) + "*",
                _ when t.IsGenericTypeDefinition =>
                    t.Assembly == typeof(object).Assembly
                        ? t.Name + "<>"
                        : (t.FullName ?? t.Name) + "<>",
                _ when t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Nullable<>) =>
                    ReprType(t.GetGenericArguments()[0]) + "?",
                _ when t.IsGenericType =>
                    WithoutGeneric(ReprType(t.GetGenericTypeDefinition())) +
                    "<" + string.Join(", ", t.GetGenericArguments().Select(ReprType)) + ">",
                _ => t.Assembly == typeof(object).Assembly ? t.Name : t.FullName ?? t.Name,
            };
    }

    private void DrawTextCell(string s, Func<string>? tooltip = null, bool framepad = false)
    {
        ImGui.TableNextColumn();
        var offset = ImGui.GetCursorScreenPos() + new Vector2(0, framepad ? ImGui.GetStyle().FramePadding.Y : 0);
        if (framepad)
            ImGui.AlignTextToFramePadding();

        ImGui.Text(s);
        if (ImGui.IsItemHovered())
        {
            ImGui.SetNextWindowPos(offset - ImGui.GetStyle().WindowPadding);
            var vp = ImGui.GetWindowViewport();
            var wrx = (vp.WorkPos.X + vp.WorkSize.X) - offset.X;

            ImGui.SetNextWindowSizeConstraints(Vector2.One, new(wrx, float.MaxValue));
            using (ImRaii.Tooltip())
            {
                using var pushedWrap = ImRaii.TextWrapPos(wrx);
                ImGui.TextWrapped(tooltip?.Invoke() ?? s);
            }
        }

        if (ImGui.IsItemClicked())
        {
            ImGui.SetClipboardText(tooltip?.Invoke() ?? s);
            Service<NotificationManager>.Get().AddNotification(
                $"已将 {ImGui.TableGetColumnName()} 复制到剪贴板。",
                this.DisplayName,
                NotificationType.Success);
        }
    }

    private void DrawCallGate()
    {
        var callGate = Service<CallGate>.Get();
        if (ImGui.Button("清除空调用门"u8))
            callGate.PurgeEmptyGates();

        using var table = ImRaii.Table("##callgate-table"u8, 5);
        if (!table.Success)
            return;

        ImGui.TableSetupColumn("名称"u8, ImGuiTableColumnFlags.DefaultSort);
        ImGui.TableSetupColumn("操作"u8);
        ImGui.TableSetupColumn("函数"u8);
        ImGui.TableSetupColumn("#"u8, ImGuiTableColumnFlags.WidthFixed, 30 * ImGuiHelpers.GlobalScale);
        ImGui.TableSetupColumn("订阅者"u8);
        ImGui.TableHeadersRow();

        var gates2 = callGate.Gates;
        if (!ReferenceEquals(gates2, this.gates) || this.gatesSorted is null)
        {
            this.gatesSorted = (this.gates = gates2).Values.ToList();
            this.gatesSorted.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        }

        foreach (var item in this.gatesSorted)
        {
            var subs = item.Subscriptions;
            for (var i = 0; i < subs.Count || i == 0; i++)
            {
                ImGui.TableNextRow();
                this.DrawTextCell(item.Name);
                this.DrawTextCell(ReprMethod(item.Action?.Method, false), () => ReprMethod(item.Action?.Method, true));
                this.DrawTextCell(ReprMethod(item.Func?.Method, false), () => ReprMethod(item.Func?.Method, true));
                if (subs.Count == 0)
                {
                    this.DrawTextCell("0");
                    continue;
                }

                this.DrawTextCell($"{i + 1}/{subs.Count}");
                this.DrawTextCell($"{subs[i].Method.DeclaringType}::{subs[i].Method.Name}");
            }
        }
    }

    private void DrawDataShare()
    {
        using var table = ImRaii.Table("###DataShareTable"u8, 5, ImGuiTableFlags.SizingFixedFit | ImGuiTableFlags.RowBg);
        if (!table.Success)
            return;

        ImGui.TableSetupColumn("共享标签"u8);
        ImGui.TableSetupColumn("查看"u8);
        ImGui.TableSetupColumn("创建者"u8);
        ImGui.TableSetupColumn("#"u8, ImGuiTableColumnFlags.WidthFixed, 30 * ImGuiHelpers.GlobalScale);
        ImGui.TableSetupColumn("使用者"u8);
        ImGui.TableHeadersRow();

        foreach (var share in Service<DataShare>.Get().GetAllShares())
        {
            ImGui.TableNextRow();
            this.DrawTextCell(share.Tag, null, true);

            ImGui.TableNextColumn();
            if (ImGui.Button($"查看##datasharetable-show-{share.Tag}"))
            {
                var index = 0;
                for (; index < this.dataView.Count; index++)
                {
                    if (this.dataView[index].Name == share.Tag)
                        break;
                }

                if (index == this.dataView.Count)
                    this.dataView.Add((share.Tag, null));
                else
                    this.dataView[index] = (share.Tag, null);

                this.nextTab = 2 + index;
            }

            this.DrawTextCell(share.CreatorPluginId.InternalName, () => share.CreatorPluginId.EffectiveWorkingId.ToString(), true);
            this.DrawTextCell(share.UserPluginIds.Length.ToString(), null, true);
            this.DrawTextCell(string.Join(", ", share.UserPluginIds.Select(c => c.InternalName)), () => string.Join("\n", share.UserPluginIds.Select(c => $"{c.InternalName} ({c.EffectiveWorkingId.ToString()}")), true);
        }
    }
}
