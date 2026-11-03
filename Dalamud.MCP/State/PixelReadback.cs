using TerraFX.Interop.DirectX;

namespace Dalamud;

/// <summary>脱离 GPU 映射生命周期的紧凑像素缓冲。</summary>
internal sealed record PixelReadback
(
    byte[]        Pixels,
    int           Pitch,
    int           SourceWidth,
    int           SourceHeight,
    CaptureRegion Region,
    DXGI_FORMAT   Format,
    string        SwapEffect
);
