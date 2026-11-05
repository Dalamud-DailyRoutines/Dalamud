namespace Dalamud;

/// <summary>截图或参考图像中的像素矩形。</summary>
internal sealed record CaptureRegion
(
    int X,
    int Y,
    int Width,
    int Height
);
