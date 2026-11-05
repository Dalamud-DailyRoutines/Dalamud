using System.ComponentModel;

namespace Dalamud;

/// <summary>按帧播放的一项键鼠操作。</summary>
internal sealed record InputAction
{
    [Description("move、click、double_click、drag、scroll、key、text、wait。")]
    public string Action { get; init; } = "click";

    [Description("起点 X；提供 screenshot 时为该截图的图像像素，否则为渲染帧像素。")]
    public double? X { get; init; }

    [Description("起点 Y，与 X 使用相同坐标基准。")]
    public double? Y { get; init; }

    [Description("drag 终点 X。")]
    public double? EndX { get; init; }

    [Description("drag 终点 Y。")]
    public double? EndY { get; init; }

    [Description("left、right、middle。")]
    public string Button { get; init; } = "left";

    [Description("组合键，使用 VirtualKey 名称，例如 [\"CONTROL\",\"A\"]。")]
    public string[]? Keys { get; init; }

    [Description("text 操作的 Unicode 文本，仅 plugin 目标支持。")]
    public string? Text { get; init; }

    [Description("scroll 的竖向滚动格数，正数向上。")]
    public int Wheel { get; init; }

    [Description("按住、拖动或等待的帧数，范围 2 至 120。")]
    public int Frames { get; init; } = 2;
}
