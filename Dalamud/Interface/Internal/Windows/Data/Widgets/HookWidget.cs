using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using Dalamud.Bindings.ImGui;
using Dalamud.Game;
using Dalamud.Hooking;
using Dalamud.Interface.Utility.Raii;
using FFXIVClientStructs.FFXIV.Component.GUI;

using Serilog;

using Windows.Win32.Foundation;
using Windows.Win32.UI.WindowsAndMessaging;

namespace Dalamud.Interface.Internal.Windows.Data.Widgets;

/// <summary>
/// Widget for displaying hook information.
/// </summary>
internal unsafe class HookWidget : IDataWindowWidget
{
    private readonly List<IDalamudHook> hookStressTestList = [];

    private Hook<MessageBoxWDelegate>? messageBoxMinHook;
    private bool hookUseMinHook;

    private int hookStressTestCount;
    private int hookStressTestMax = 1000;
    private int hookStressTestWait = 100;
    private int hookStressTestMaxDegreeOfParallelism = 10;
    private StressTestHookTarget hookStressTestHookTarget = StressTestHookTarget.Random;
    private bool hookStressTestRunning;

    private MessageBoxWDelegate? messageBoxWOriginal;
    private AddonFinalizeDelegate? addonFinalizeOriginal;

    private nint address;

    private delegate int MessageBoxWDelegate(
        IntPtr hWnd,
        [MarshalAs(UnmanagedType.LPWStr)] string text,
        [MarshalAs(UnmanagedType.LPWStr)] string caption,
        MESSAGEBOX_STYLE type);

    private delegate void AddonFinalizeDelegate(AtkUnitManager* unitManager, AtkUnitBase** atkUnitBase);

    private enum StressTestHookTarget
    {
        MessageBoxW,
        AddonFinalize,
        Random,
    }

    /// <inheritdoc/>
    public string DisplayName { get; init; } = "Hook 测试";

    /// <inheritdoc/>
    public string[]? CommandShortcuts { get; init; } = ["hook"];

    /// <inheritdoc/>
    public bool Ready { get; set; }

    /// <inheritdoc/>
    public void Load()
    {
        this.Ready = true;

        var sigScanner = Service<TargetSigScanner>.Get();
        this.address = sigScanner.ScanText("E8 ?? ?? ?? ?? 48 83 EF 01 75 D5");
    }

    /// <inheritdoc/>
    public void Draw()
    {
        try
        {
            ImGui.Checkbox("使用 MinHook（仅适用于常规 Hook，AsmHook 仅支持 Reloaded）"u8, ref this.hookUseMinHook);

            ImGui.Separator();

            if (ImGui.Button("创建"u8))
                this.messageBoxMinHook = Hook<MessageBoxWDelegate>.FromSymbol("User32", "MessageBoxW", this.MessageBoxWDetour, this.hookUseMinHook);

            if (ImGui.Button("启用"u8))
                this.messageBoxMinHook?.Enable();

            if (ImGui.Button("禁用"u8))
                this.messageBoxMinHook?.Disable();

            if (ImGui.Button("调用原函数"u8))
                this.messageBoxMinHook?.Original(IntPtr.Zero, "来自 .Original 的问候", "Hook 测试", MESSAGEBOX_STYLE.MB_OK);

            if (ImGui.Button("释放"u8))
            {
                this.messageBoxMinHook?.Dispose();
                this.messageBoxMinHook = null;
            }

            if (ImGui.Button("测试"u8))
                _ = global::Windows.Win32.PInvoke.MessageBox(HWND.Null, "你好", "问候", MESSAGEBOX_STYLE.MB_OK);

            if (this.messageBoxMinHook != null)
                ImGui.Text("已启用：" + (this.messageBoxMinHook?.IsEnabled switch
                {
                    true => "是",
                    false => "否",
                    null => "尚未创建",
                }));

            ImGui.Separator();

            using (ImRaii.Disabled(this.hookStressTestRunning))
            {
                ImGui.Text("压力测试"u8);

                if (ImGui.InputInt("最大次数"u8, ref this.hookStressTestMax))
                    this.hookStressTestCount = 0;

                ImGui.InputInt("等待时间（ms）"u8, ref this.hookStressTestWait);
                ImGui.InputInt("最大并行度"u8, ref this.hookStressTestMaxDegreeOfParallelism);

                using (var combo = ImRaii.Combo("目标"u8, HookTargetToString(this.hookStressTestHookTarget)))
                {
                    if (combo.Success)
                    {
                        foreach (var target in Enum.GetValues<StressTestHookTarget>())
                        {
                            if (ImGui.Selectable(HookTargetToString(target), this.hookStressTestHookTarget == target))
                                this.hookStressTestHookTarget = target;
                        }
                    }
                }

                if (ImGui.Button("开始压力测试"u8))
                {
                    Task.Run(() =>
                    {
                        this.hookStressTestRunning = true;
                        this.hookStressTestCount = 0;
                        Parallel.For(
                            0,
                            this.hookStressTestMax,
                            new ParallelOptions
                            {
                                MaxDegreeOfParallelism = this.hookStressTestMaxDegreeOfParallelism,
                            },
                            _ =>
                            {
                                this.hookStressTestList.Add(this.HookTarget(this.hookStressTestHookTarget));
                                this.hookStressTestCount++;
                                Thread.Sleep(this.hookStressTestWait);
                            });
                    }).ContinueWith(t =>
                    {
                        if (t.IsFaulted)
                        {
                            Log.Error(t.Exception, "压力测试失败");
                        }
                        else
                        {
                            Log.Information("压力测试完成");
                        }

                        this.hookStressTestRunning = false;
                        this.hookStressTestList.ForEach(hook =>
                        {
                            hook.Dispose();
                        });
                        this.hookStressTestList.Clear();
                    });
                }
            }

            ImGui.Text("状态：" + (this.hookStressTestRunning ? "运行中" : "空闲"));
            ImGui.ProgressBar(this.hookStressTestCount / (float)this.hookStressTestMax, new System.Numerics.Vector2(0, 0), $"{this.hookStressTestCount}/{this.hookStressTestMax}");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "捕获到 Hook 错误");
        }
    }

    private static string HookTargetToString(StressTestHookTarget target)
    {
        return target switch
        {
            StressTestHookTarget.MessageBoxW => "MessageBoxW（Hook）",
            StressTestHookTarget.AddonFinalize => "AddonFinalize（Hook）",
            _ => target.ToString(),
        };
    }

    private int MessageBoxWDetour(IntPtr hwnd, string text, string caption, MESSAGEBOX_STYLE type)
    {
        Log.Information("[DATAHOOK] {Hwnd} {Text} {Caption} {Type}", hwnd, text, caption, type);

        var result = this.messageBoxWOriginal!(hwnd, "是否触发访问冲突？", caption, MESSAGEBOX_STYLE.MB_YESNO);

        if (result == (int)MESSAGEBOX_RESULT.IDYES)
        {
            Marshal.ReadByte(IntPtr.Zero);
        }

        return result;
    }

    private void OnAddonFinalize(AtkUnitManager* unitManager, AtkUnitBase** atkUnitBase)
    {
        Log.Information("OnAddonFinalize");
        this.addonFinalizeOriginal!(unitManager, atkUnitBase);
    }

    private IDalamudHook HookMessageBoxW()
    {
        var hook = Hook<MessageBoxWDelegate>.FromSymbol(
            "User32",
            "MessageBoxW",
            this.MessageBoxWDetour,
            this.hookUseMinHook);

        this.messageBoxWOriginal = hook.Original;
        hook.Enable();
        return hook;
    }

    private IDalamudHook HookAddonFinalize()
    {
        var hook = Hook<AddonFinalizeDelegate>.FromAddress(this.address, this.OnAddonFinalize);

        this.addonFinalizeOriginal = hook.Original;
        hook.Enable();
        return hook;
    }

    private IDalamudHook HookTarget(StressTestHookTarget target)
    {
        if (target == StressTestHookTarget.Random)
        {
            target = (StressTestHookTarget)Random.Shared.Next(0, 2);
        }

        return target switch
        {
            StressTestHookTarget.MessageBoxW => this.HookMessageBoxW(),
            StressTestHookTarget.AddonFinalize => this.HookAddonFinalize(),
            _ => throw new ArgumentOutOfRangeException(nameof(target), target, null),
        };
    }
}
