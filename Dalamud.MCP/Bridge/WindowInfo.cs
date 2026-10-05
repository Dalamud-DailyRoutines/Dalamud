using System.Globalization;
using System.Text;
using Dalamud.Interface.Internal;
using TerraFX.Interop.DirectX;

namespace Dalamud;

/// <summary>
/// 报告游戏窗口的坐标基准：渲染帧尺寸、客户区尺寸与两者比例。
/// </summary>
internal static unsafe class WindowInfo
{
    /// <summary>
    /// 取回游戏窗口句柄。
    /// </summary>
    /// <returns>窗口句柄，不可用时为 0。</returns>
    public static nint GetGameWindow()
    {
        var swapChain = SwapChainHelper.GameDeviceSwapChain;
        if (swapChain is null)
            return 0;

        var desc = default(DXGI_SWAP_CHAIN_DESC);
        if (swapChain->GetDesc(&desc).FAILED)
            return 0;

        return desc.OutputWindow;
    }

    /// <summary>
    /// 取回渲染帧尺寸。
    /// </summary>
    /// <returns>渲染帧宽高，不可用时为 0。</returns>
    public static (int Width, int Height) GetRenderSize()
    {
        var swapChain = SwapChainHelper.GameDeviceSwapChain;
        if (swapChain is null)
            return (0, 0);

        var desc = default(DXGI_SWAP_CHAIN_DESC);
        if (swapChain->GetDesc(&desc).FAILED)
            return (0, 0);

        return ((int)desc.BufferDesc.Width, (int)desc.BufferDesc.Height);
    }

    /// <summary>
    /// 取回客户区尺寸，单位为屏幕逻辑像素。
    /// </summary>
    /// <returns>客户区宽高，不可用时为 0。</returns>
    public static (int Width, int Height) GetClientSize()
    {
        var window = GetGameWindow();
        if (window == 0 || !NativeApi.GetClientRect(window, out var client))
            return (0, 0);

        return (client.Right - client.Left, client.Bottom - client.Top);
    }

    /// <summary>
    /// 渲染窗口与屏幕信息。
    /// </summary>
    /// <returns>JSON 文本。</returns>
    public static string Describe()
    {
        var window  = GetGameWindow();
        var builder = new StringBuilder(768);

        builder.Append("{\"handle\":\"").Append(Format(window)).Append('"');

        if (window == 0)
        {
            builder.Append(",\"available\":false}");
            return builder.ToString();
        }

        builder.Append(",\"available\":true");

        var (renderWidth, renderHeight) = GetRenderSize();
        var (clientWidth, clientHeight) = GetClientSize();

        builder.Append(",\"renderWidth\":").Append(renderWidth);
        builder.Append(",\"renderHeight\":").Append(renderHeight);
        builder.Append(",\"clientWidth\":").Append(clientWidth);
        builder.Append(",\"clientHeight\":").Append(clientHeight);

        if (renderWidth > 0 && renderHeight > 0)
        {
            builder.Append(",\"clientScaleX\":").Append(((double)clientWidth  / renderWidth).ToString("F4", CultureInfo.InvariantCulture));
            builder.Append(",\"clientScaleY\":").Append(((double)clientHeight / renderHeight).ToString("F4", CultureInfo.InvariantCulture));
        }

        if (NativeApi.GetWindowRect(window, out var rect))
        {
            builder.Append(",\"windowLeft\":").Append(rect.Left);
            builder.Append(",\"windowTop\":").Append(rect.Top);
        }

        builder.Append(",\"virtualScreenLeft\":").Append(NativeApi.GetSystemMetrics(NativeApi.SM_XVIRTUALSCREEN));
        builder.Append(",\"virtualScreenTop\":").Append(NativeApi.GetSystemMetrics(NativeApi.SM_YVIRTUALSCREEN));
        builder.Append(",\"virtualScreenWidth\":").Append(NativeApi.GetSystemMetrics(NativeApi.SM_CXVIRTUALSCREEN));
        builder.Append(",\"virtualScreenHeight\":").Append(NativeApi.GetSystemMetrics(NativeApi.SM_CYVIRTUALSCREEN));
        builder.Append(",\"foreground\":").Append(NativeApi.GetForegroundWindow() == window ? "true" : "false");
        builder.Append(",\"minimized\":").Append(NativeApi.IsIconic(window) ? "true" : "false");
        builder.Append('}');

        return builder.ToString();
    }

    /// <summary>
    /// 把地址渲染成 0x 前缀文本。
    /// </summary>
    /// <param name="address">地址。</param>
    /// <returns>地址文本。</returns>
    public static string Format
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);
}
