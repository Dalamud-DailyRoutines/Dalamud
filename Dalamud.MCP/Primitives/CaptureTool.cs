using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ModelContextProtocol.Protocol;

namespace Dalamud;

/// <summary>获取实时画面或裁剪已缓存的截图，并返回可供输入直接引用的坐标变换。</summary>
internal static class CaptureTool
{
    public static async Task<IEnumerable<ContentBlock>> Run
    (
        [Description("最长边像素数，0 为原尺寸，1 至 4096 按比例缩小或放大。")]
        int maxDimension = 1600,
        [Description("结构化区域 {X,Y,Width,Height}。实时截图使用渲染帧像素；提供 screenshot 时使用该截图的图像像素。省略为全图。")]
        CaptureRegion? region = null,
        [Description("已有截图编号。提供时只裁剪缓存图像，保持同一时刻；省略时抓取新帧。")]
        string? screenshot = null,
        CancellationToken cancellationToken = default
    )
    {
        cancellationToken.ThrowIfCancellationRequested();
        var frame = screenshot is null ?
                        await ScreenCapture.CaptureAsync(maxDimension, region, cancellationToken).ConfigureAwait(false) :
                        await Task.Run(() => ScreenCapture.Crop(CaptureStore.Get(screenshot), region, maxDimension), cancellationToken).ConfigureAwait(false);
        CaptureStore.Add(frame);
        MCPRuntime.Trace.Write("capture", $"{frame.Id} output={frame.Width}x{frame.Height} source={frame.SourceWidth}x{frame.SourceHeight}");
        return
        [
            new TextContentBlock { Text = JsonSerializer.Serialize(Describe(frame)) },
            ImageContentBlock.FromBytes(frame.Png, "image/png")
        ];
    }

    public static object Describe(CapturedFrame frame) => new
    {
        screenshot   = frame.Id,
        capturedAt   = frame.CapturedAt,
        width        = frame.Width,
        height       = frame.Height,
        sourceWidth  = frame.SourceWidth,
        sourceHeight = frame.SourceHeight,
        region       = frame.Region,
        transform = new
        {
            renderX                    = frame.RenderX,
            renderY                    = frame.RenderY,
            renderPixelsPerImagePixelX = frame.ScaleX,
            renderPixelsPerImagePixelY = frame.ScaleY
        },
        coordinateSpace = "image_pixels",
        inputHint       = "input.screenshot 使用此编号，X、Y 直接取本图像像素；左上角为 0,0。",
        frame.Format,
        frame.SwapEffect,
        byteLength = frame.Png.Length
    };
}
