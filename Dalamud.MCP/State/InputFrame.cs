using FFXIVClientStructs.FFXIV.Client.System.Input;

namespace Dalamud;

/// <summary>一帧合成输入的完整状态。</summary>
internal sealed record InputFrame
(
    double?          X,
    double?          Y,
    MouseButtonFlags Buttons,
    ushort[]         Keys,
    int              Wheel = 0,
    string?          Text  = null
);
