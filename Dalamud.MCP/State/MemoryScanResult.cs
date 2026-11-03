using System.Collections.Generic;

namespace Dalamud;

/// <summary>一次值扫描保留的候选与完成状态。</summary>
internal sealed record MemoryScanResult
(
    List<nint>         Candidates,
    List<NumericValue> Values,
    int                Total,
    bool               Truncated
);
