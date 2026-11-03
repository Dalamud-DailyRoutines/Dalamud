using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Drawing.Drawing2D;
using Dalamud.Interface.Internal;
using ModelContextProtocol;
using TerraFX.Interop.DirectX;
using TerraFX.Interop.Windows;

namespace Dalamud;

/// <summary>
/// 在 ImGui 渲染完成、交换链提交之前抓取后备缓冲，因此画面包含插件界面。
/// </summary>
internal static class ScreenCapture
{
    private const int FRAME_WAIT_MILLISECONDS = 5000;

    public static async Task<CapturedFrame> CaptureAsync(int maxDimension, CaptureRegion? region, CancellationToken cancellationToken)
    {
        if (maxDimension is < 0 or > 4096)
            throw new McpException("maxDimension 必须在 0 至 4096 之间。");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(FRAME_WAIT_MILLISECONDS);
        var token   = deadline.Token;
        var manager = Service<InterfaceManager>.GetNullable() ?? throw new McpException("界面管理器尚未就绪。");
        var readback = await manager.RunAfterImGuiRender
                       (() =>
                           {
                               token.ThrowIfCancellationRequested();
                               return Readback(region);
                           }
                       ).WaitAsync(token).ConfigureAwait(false);

        return await Task.Run(() => Encode(readback, maxDimension), cancellationToken).ConfigureAwait(false);
    }

    public static CapturedFrame Crop(CapturedFrame source, CaptureRegion? region, int maxDimension)
    {
        if (maxDimension is < 0 or > 4096)
            throw new McpException("maxDimension 必须在 0 至 4096 之间。");

        var       crop   = ValidateRegion(region, source.Width, source.Height);
        using var stream = new MemoryStream(source.Png, false);
        using var bitmap = new Bitmap(stream);
        var       width  = crop.Width;
        var       height = crop.Height;

        if (maxDimension > 0)
        {
            var scale = (double)maxDimension / Math.Max(width, height);
            width  = Math.Max(1, (int)Math.Round(width  * scale));
            height = Math.Max(1, (int)Math.Round(height * scale));
        }

        using var output = new Bitmap(width, height, PixelFormat.Format32bppArgb);

        using (var graphics = Graphics.FromImage(output))
        {
            graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            graphics.DrawImage(bitmap, new Rectangle(0, 0, width, height), new Rectangle(crop.X, crop.Y, crop.Width, crop.Height), GraphicsUnit.Pixel);
        }

        using var encoded = new MemoryStream();
        output.Save(encoded, ImageFormat.Png);
        var left   = source.Region.X + (int)((long)crop.X                 * source.Region.Width  / source.Width);
        var top    = source.Region.Y + (int)((long)crop.Y                 * source.Region.Height / source.Height);
        var right  = source.Region.X + (int)((long)(crop.X + crop.Width)  * source.Region.Width  / source.Width);
        var bottom = source.Region.Y + (int)((long)(crop.Y + crop.Height) * source.Region.Height / source.Height);
        return new CapturedFrame
        (
            encoded.ToArray(),
            width,
            height,
            source.SourceWidth,
            source.SourceHeight,
            new CaptureRegion(left, top, right - left, bottom - top),
            source.Format,
            source.SwapEffect
        )
        {
            CapturedAt = source.CapturedAt,
            RenderX    = source.RenderX + (crop.X * source.ScaleX),
            RenderY    = source.RenderY + (crop.Y * source.ScaleY),
            ScaleX     = source.ScaleX * crop.Width  / width,
            ScaleY     = source.ScaleY * crop.Height / height
        };
    }

    private static CaptureRegion ValidateRegion(CaptureRegion? region, int width, int height)
    {
        var crop = region ?? new CaptureRegion(0, 0, width, height);
        if (crop.X < 0 || crop.Y < 0 || crop.Width <= 0 || crop.Height <= 0 || (long)crop.X + crop.Width > width || (long)crop.Y + crop.Height > height)
            throw new McpException("region 必须为图像范围内的正面积矩形。");

        return crop;
    }

    private static unsafe PixelReadback Readback(CaptureRegion? region)
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

            var crop   = ValidateRegion(region, width, height);
            var format = desc.Format;
            var bytesPerPixel = format switch
            {
                DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT => 8,
                DXGI_FORMAT.DXGI_FORMAT_B8G8R8A8_UNORM or DXGI_FORMAT.DXGI_FORMAT_B8G8R8A8_UNORM_SRGB
                    or DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM or DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB
                    or DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UNORM => 4,
                _ => throw new McpException($"不支持的后备缓冲格式 {format}。")
            };
            if (desc.SampleDesc.Count != 1)
                throw new McpException("不支持多重采样后备缓冲截图。");

            desc.Width          = (uint)crop.Width;
            desc.Height         = (uint)crop.Height;
            desc.Usage          = D3D11_USAGE.D3D11_USAGE_STAGING;
            desc.BindFlags      = 0;
            desc.CPUAccessFlags = (uint)D3D11_CPU_ACCESS_FLAG.D3D11_CPU_ACCESS_READ;
            desc.MiscFlags      = 0;

            if (device->CreateTexture2D(&desc, null, &staging).FAILED)
                throw new McpException($"无法创建 {width}x{height} {desc.Format} 的暂存纹理。");

            var box = new D3D11_BOX
            {
                left   = (uint)crop.X,
                top    = (uint)crop.Y,
                front  = 0,
                right  = (uint)(crop.X + crop.Width),
                bottom = (uint)(crop.Y + crop.Height),
                back   = 1
            };
            context->CopySubresourceRegion((ID3D11Resource*)staging, 0, 0, 0, 0, (ID3D11Resource*)backBuffer, 0, &box);

            var mapped = default(D3D11_MAPPED_SUBRESOURCE);
            if (context->Map((ID3D11Resource*)staging, 0, D3D11_MAP.D3D11_MAP_READ, 0, &mapped).FAILED)
                throw new McpException("无法映射暂存纹理以读回像素。");

            try
            {
                var pitch  = checked(crop.Width * bytesPerPixel);
                var pixels = new byte[checked(pitch * crop.Height)];
                for (var row = 0; row < crop.Height; row++)
                    Marshal.Copy((nint)((byte*)mapped.pData + (row * mapped.RowPitch)), pixels, row * pitch, pitch);

                var swapDesc = default(DXGI_SWAP_CHAIN_DESC);
                var swapEffect = swapChain->GetDesc(&swapDesc).FAILED ?
                                     "unknown" :
                                     swapDesc.SwapEffect.ToString();

                return new PixelReadback(pixels, pitch, width, height, crop, format, swapEffect);
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

    private static unsafe CapturedFrame Encode(PixelReadback readback, int maxDimension)
    {
        fixed (byte* source = readback.Pixels)
        {
            var (png, width, height) = EncodePng(source, readback.Pitch, 0, 0, readback.Region.Width, readback.Region.Height, readback.Format, maxDimension);
            return new CapturedFrame
                (png, width, height, readback.SourceWidth, readback.SourceHeight, readback.Region, readback.Format.ToString(), readback.SwapEffect);
        }
    }

    private static unsafe (byte[] Png, int Width, int Height) EncodePng
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

        if (maxDimension > 0)
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

    private static unsafe void ConvertRow
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
            var sourceColumn = cropLeft    + (int)((long)column * cropWidth / targetWidth);
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
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM:
                case DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
                {
                    var pixel = source + ((long)sourceColumn * 4);
                    target[0] = pixel[2];
                    target[1] = pixel[1];
                    target[2] = pixel[0];
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R10G10B10A2_UNORM:
                {
                    var packed = *(uint*)(source + ((long)sourceColumn * 4));
                    target[0] = (byte)(((packed >> 20) & 0x3FF) >> 2);
                    target[1] = (byte)(((packed >> 10) & 0x3FF) >> 2);
                    target[2] = (byte)((packed         & 0x3FF) >> 2);
                    break;
                }

                case DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT:
                {
                    var pixel = (Half*)(source + ((long)sourceColumn * 8));
                    target[0] = ToByte(pixel[2]);
                    target[1] = ToByte(pixel[1]);
                    target[2] = ToByte(pixel[0]);
                    break;
                }

                default:
                    throw new McpException($"不支持的后备缓冲格式 {format}。");
            }

            target[3] = 0xFF;
        }
    }

    private static byte ToByte
    (
        Half value
    ) =>
        (byte)Math.Clamp((int)MathF.Round((float)value * 255f), 0, 255);
}
