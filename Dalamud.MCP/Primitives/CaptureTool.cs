using System.Collections.Generic;
using System.Globalization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Dalamud;

/// <summary>
/// <c>capture</c> 原语：抓取一帧画面并附上坐标基准，可按区域裁剪放大。
/// </summary>
internal static class CaptureTool
{
    /// <summary>
    /// 抓取一帧。
    /// </summary>
    /// <param name="maxDimension">输出图像最长边上限，0 表示按源分辨率原样输出；给出 region 时该区域会按此上限等比放大。</param>
    /// <param name="region">只抓取该区域，形如 <c>x,y,width,height</c>，以渲染帧像素为基准，用于放大细节辨读。</param>
    /// <returns>文本与图像内容块。</returns>
    public static IEnumerable<ContentBlock> Run
    (
        int     maxDimension = 0,
        string? region       = null
    )
    {
        var (cropX, cropY, cropWidth, cropHeight) = ParseRegion(region);

        var (png, width, height, sourceWidth, sourceHeight, format, swapEffect) = ScreenCapture.Capture
        (
            maxDimension <= 0 ? 0 : Math.Clamp(maxDimension, 64, 4096),
            cropX,
            cropY,
            cropWidth,
            cropHeight
        );

        var window = WindowInfo.Describe();

        MCPRuntime.Trace.Write("capture", $"png={png.Length} bytes out={width}x{height} source={sourceWidth}x{sourceHeight} format={format} swapEffect={swapEffect} region={region}");

        yield return new TextContentBlock
        {
            Text = "{\"outputWidth\":"                  +
                   width                                +
                   ",\"outputHeight\":"                 +
                   height                               +
                   ",\"sourceWidth\":"                  +
                   sourceWidth                          +
                   ",\"sourceHeight\":"                 +
                   sourceHeight                         +
                   ",\"format\":"                       +
                   ValueFormatter.Format(format, 0)     +
                   ",\"swapEffect\":"                   +
                   ValueFormatter.Format(swapEffect, 0) +
                   ",\"byteLength\":"                   +
                   png.Length                           +
                   ",\"region\":"                       +
                   ValueFormatter.Format(region, 0)     +
                   ",\"window\":"                       +
                   window                               +
                   "}"
        };

        yield return ImageContentBlock.FromBytes(png, "image/png");
    }

    private static (int X, int Y, int Width, int Height) ParseRegion
    (
        string? region
    )
    {
        if (string.IsNullOrWhiteSpace(region))
            return (0, 0, 0, 0);

        var parts = region.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 4)
            throw new McpException("region 需要四个以逗号分隔的整数: x,y,width,height。");

        return (int.Parse(parts[0],    CultureInfo.InvariantCulture),
                   int.Parse(parts[1], CultureInfo.InvariantCulture),
                   int.Parse(parts[2], CultureInfo.InvariantCulture),
                   int.Parse(parts[3], CultureInfo.InvariantCulture));
    }
}
