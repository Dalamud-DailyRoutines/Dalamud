using ModelContextProtocol;

namespace Dalamud;

/// <summary>图像及其相对游戏后备缓冲的坐标变换。</summary>
internal sealed record CapturedFrame
(
    byte[]        Png,
    int           Width,
    int           Height,
    int           SourceWidth,
    int           SourceHeight,
    CaptureRegion Region,
    string        Format,
    string        SwapEffect
)
{
    public string Id { get; } = Guid.NewGuid().ToString("N");

    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;

    public double RenderX { get; init; } = Region.X;

    public double RenderY { get; init; } = Region.Y;

    public double ScaleX { get; init; } = (double)Region.Width / Width;

    public double ScaleY { get; init; } = (double)Region.Height / Height;

    public (double X, double Y) ToRender(double x, double y)
    {
        if (!double.IsFinite(x) || !double.IsFinite(y) || x < 0 || y < 0 || x >= this.Width || y >= this.Height)
            throw new McpException("坐标超出参考截图范围。");

        return (this.RenderX    + (x * this.ScaleX),
                   this.RenderY + (y * this.ScaleY));
    }
}
