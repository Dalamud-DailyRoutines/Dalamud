using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using Dalamud.Interface.Internal;
using Dalamud.Utility;
using ModelContextProtocol;
using TerraFX.Interop.DirectX;
using TerraFX.Interop.Windows;

namespace Dalamud;

/// <summary>
/// 在 ImGui 渲染完成、交换链提交之前抓取后备缓冲，因此画面包含插件界面。
/// </summary>
internal static unsafe class ScreenCapture
{
    private const int FRAME_WAIT_MILLISECONDS = 5000;

    /// <summary>
    /// 抓取一帧。
    /// </summary>
    /// <param name="maxDimension">最长边上限，超出则按比例缩小。</param>
    /// <param name="cropX">裁剪区左上角 X，以渲染帧像素为基准。</param>
    /// <param name="cropY">裁剪区左上角 Y，以渲染帧像素为基准。</param>
    /// <param name="cropWidth">裁剪区宽度，0 表示取到右边界。</param>
    /// <param name="cropHeight">裁剪区高度，0 表示取到下边界。</param>
    /// <returns>PNG 字节、输出尺寸、源尺寸、后备缓冲格式与交换效果。</returns>
    public static (byte[] Png, int Width, int Height, int SourceWidth, int SourceHeight, string Format, string SwapEffect) Capture
    (
        int maxDimension,
        int cropX,
        int cropY,
        int cropWidth,
        int cropHeight
    )
    {
        MCPRuntime.Trace.Write("capture", "等待界面管理器");

        var manager = Service<InterfaceManager>.GetNullable()
                      ?? throw new McpException("界面管理器尚未就绪，暂时无法抓帧。");

        MCPRuntime.Trace.Write("capture", "已入队抓帧请求");

        var task = manager.RunAfterImGuiRender(() => CaptureImmediate(maxDimension, cropX, cropY, cropWidth, cropHeight));

        try
        {
            if (!task.Wait(FRAME_WAIT_MILLISECONDS))
            {
                MCPRuntime.Trace.Write("capture", "等待渲染一帧超时");
                throw new McpException("等待游戏绘制一帧超时，抓帧回调没有被执行。");
            }
        }
        catch (AggregateException)
        {
            // 由下面的 GetResultSafely 重新抛出原始异常。
        }

        var captured = task.GetResultSafely();
        MCPRuntime.Trace.Write("capture", $"抓帧完成 out={captured.Width}x{captured.Height}");

        return captured;
    }

    private static (byte[] Png, int Width, int Height, int SourceWidth, int SourceHeight, string Format, string SwapEffect) CaptureImmediate
    (
        int maxDimension,
        int cropX,
        int cropY,
        int cropWidth,
        int cropHeight
    )
    {
        var swapChain = SwapChainHelper.GameDeviceSwapChain;
        if (swapChain is null)
            throw new McpException("暂不可用：游戏交换链尚未初始化。");

        ID3D11Device*        device     = null;
        ID3D11DeviceContext* context    = null;
        ID3D11Texture2D*     backBuffer = null;
        ID3D11Texture2D*     staging    = null;

        try
        {
            var deviceId = IID.IID_ID3D11Device;
            if (swapChain->GetDevice(&deviceId, (void**)&device).FAILED)
                throw new McpException("无法从交换链取回 D3D11 设备。");

            device->GetImmediateContext(&context);

            var textureId = IID.IID_ID3D11Texture2D;
            if (swapChain->GetBuffer(0, &textureId, (void**)&backBuffer).FAILED)
                throw new McpException("无法取回交换链的第 0 号后备缓冲。");

            var desc = default(D3D11_TEXTURE2D_DESC);
            backBuffer->GetDesc(&desc);

            var width  = (int)desc.Width;
            var height = (int)desc.Height;

            var left   = Math.Clamp(cropX, 0, width - 1);
            var top    = Math.Clamp(cropY, 0, height - 1);
            var right  = cropWidth  <= 0 ? width  : Math.Min(left + cropWidth,  width);
            var bottom = cropHeight <= 0 ? height : Math.Min(top  + cropHeight, height);

            desc.Usage          = D3D11_USAGE.D3D11_USAGE_STAGING;
            desc.BindFlags      = 0;
            desc.CPUAccessFlags = (uint)D3D11_CPU_ACCESS_FLAG.D3D11_CPU_ACCESS_READ;
            desc.MiscFlags      = 0;

            if (device->CreateTexture2D(&desc, null, &staging).FAILED)
                throw new McpException($"无法创建 {width}x{height} {desc.Format} 的暂存纹理。");

            context->CopyResource((ID3D11Resource*)staging, (ID3D11Resource*)backBuffer);

            var mapped = default(D3D11_MAPPED_SUBRESOURCE);
            if (context->Map((ID3D11Resource*)staging, 0, D3D11_MAP.D3D11_MAP_READ, 0, &mapped).FAILED)
                throw new McpException("无法映射暂存纹理以读回像素。");

            try
            {
                var (png, outWidth, outHeight) = EncodePng
                (
                    (byte*)mapped.pData,
                    (int)mapped.RowPitch,
                    left,
                    top,
                    right  - left,
                    bottom - top,
                    desc.Format,
                    maxDimension
                );

                var swapDesc = default(DXGI_SWAP_CHAIN_DESC);
                var swapEffect = swapChain->GetDesc(&swapDesc).FAILED
                                     ? "unknown"
                                     : swapDesc.SwapEffect.ToString();

                return (png, outWidth, outHeight, width, height, desc.Format.ToString(), swapEffect);
            }
            finally
            {
                context->Unmap((ID3D11Resource*)staging, 0);
            }
        }
        finally
        {
            if (staging is not null)
                staging->Release();

            if (backBuffer is not null)
                backBuffer->Release();

            if (context is not null)
                context->Release();

            if (device is not null)
                device->Release();
        }
    }

    private static (byte[] Png, int Width, int Height) EncodePng
    (
        byte*       source,
        int         sourcePitch,
        int         cropLeft,
        int         cropTop,
        int         cropWidth,
        int         cropHeight,
        DXGI_FORMAT format,
        int         maxDimension
    )
    {
        var targetWidth  = cropWidth;
        var targetHeight = cropHeight;

        if (maxDimension > 0 && Math.Max(cropWidth, cropHeight) > maxDimension)
        {
            var scale = (double)maxDimension / Math.Max(cropWidth, cropHeight);
            targetWidth  = Math.Max(1, (int)(cropWidth  * scale));
            targetHeight = Math.Max(1, (int)(cropHeight * scale));
        }

        using var bitmap = new Bitmap(targetWidth, targetHeight, PixelFormat.Format32bppArgb);
        var data = bitmap.LockBits
        (
            new Rectangle(0, 0, targetWidth, targetHeight),
            ImageLockMode.WriteOnly,
            PixelFormat.Format32bppArgb
        );

        try
        {
            for (var row = 0; row < targetHeight; row++)
            {
                var sourceRow = cropTop + (int)((long)row * cropHeight / targetHeight);

                ConvertRow
                (
                    source            + ((long)sourceRow * sourcePitch),
                    (byte*)data.Scan0 + ((long)row       * data.Stride),
                    targetWidth,
                    cropLeft,
                    cropWidth,
                    format
                );
            }
        }
        finally
        {
            bitmap.UnlockBits(data);
        }

        using var stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Png);
        return (stream.ToArray(), targetWidth, targetHeight);
    }

    private static void ConvertRow
    (
        byte*       source,
        byte*       destination,
        int         targetWidth,
        int         cropLeft,
        int         cropWidth,
        DXGI_FORMAT format
    )
    {
        for (var column = 0; column < targetWidth; column++)
        {
            var sourceColumn = cropLeft + (int)((long)column * cropWidth / targetWidth);
            var target       = destination + ((long)column * 4);

            switch (format)
            {
                case DXGI_FORMAT.DXGI_FORMAT_B8G8R8A8_UNORM:
                case DXGI_FORMAT.DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
                {
                    var pixel = source + ((long)sourceColumn * 4);
                    target[0] = pixel[0];
                    target[1] = pixel[1];
                    target[2] = pixel[2];
                    target[3] = 0xFF;
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM:
                case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
                {
                    var pixel = source + ((long)sourceColumn * 4);
                    target[0] = pixel[2];
                    target[1] = pixel[1];
                    target[2] = pixel[0];
                    target[3] = 0xFF;
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UNORM:
                {
                    var packed = *(uint*)(source + ((long)sourceColumn * 4));
                    target[0] = (byte)(((packed >> 20) & 0x3FF) >> 2);
                    target[1] = (byte)(((packed >> 10) & 0x3FF) >> 2);
                    target[2] = (byte)((packed & 0x3FF) >> 2);
                    target[3] = 0xFF;
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT:
                {
                    var pixel = (Half*)(source + ((long)sourceColumn * 8));
                    target[0] = ToByte(pixel[2]);
                    target[1] = ToByte(pixel[1]);
                    target[2] = ToByte(pixel[0]);
                    target[3] = 0xFF;
                    break;
                }

                default:
                    throw new McpException($"不支持的后备缓冲格式 {format}。");
            }
        }
    }

    private static byte ToByte
    (
        Half value
    ) =>
        (byte)Math.Clamp((int)MathF.Round((float)value * 255f), 0, 255);
}
