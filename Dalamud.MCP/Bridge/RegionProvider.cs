using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Dalamud.Memory;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 取回要扫描的内存区域：默认是主模块，也可以扩展到整个可读地址空间并按范围裁剪。
/// </summary>
internal static class RegionProvider
{
    private const uint MEM_COMMIT_STATE       = 0x1000;
    private const uint PAGE_READWRITE_PROTECT = 0x04;
    private const uint PAGE_GUARD_OR_NOACCESS = 0x100 | 0x01;
    private const uint PAGE_READABLE_MASK     = 0x02  | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    /// <summary>
    /// 取回要扫描的区域。
    /// </summary>
    /// <param name="whole">是否扫描整个可读地址空间。</param>
    /// <param name="moduleName">限定模块名，省略时使用主模块。</param>
    /// <param name="rangeStart">范围起点，0 表示不限制。</param>
    /// <param name="rangeEnd">范围终点，0 表示不限制。</param>
    /// <returns>区域列表。</returns>
    public static IReadOnlyList<MemoryRegion> GetReadableRegions
    (
        bool    whole,
        string? moduleName,
        nint    rangeStart = 0,
        nint    rangeEnd   = 0
    )
    {
        List<MemoryRegion> regions;

        var module = whole ? null : FindModule(moduleName);

        if (module is not null)
        {
            regions =
            [
                new MemoryRegion
                (
                    (ulong)module.BaseAddress.ToInt64(),
                    (ulong)module.ModuleMemorySize,
                    MEM_COMMIT_STATE,
                    PAGE_READWRITE_PROTECT
                )
            ];
        }
        else
        {
            regions = [.. AddressSpaceAnalysis.ScanRegions().Where(IsReadable)];
        }

        if (rangeStart == 0 && rangeEnd == 0)
            return regions;

        var start   = rangeStart == 0 ? 0UL : (ulong)rangeStart;
        var end     = rangeEnd   == 0 ? ulong.MaxValue : (ulong)rangeEnd;
        var clipped = new List<MemoryRegion>();

        foreach (var region in regions)
        {
            var from = Math.Max(region.Start, start);
            var to   = Math.Min(region.End, end);

            if (to > from)
                clipped.Add(new MemoryRegion(from, to - from, region.State, region.Protect));
        }

        return clipped;
    }

    private static bool IsReadable
    (
        MemoryRegion region
    )
    {
        if (!region.IsCommitted)
            return false;

        if ((region.Protect & PAGE_GUARD_OR_NOACCESS) != 0)
            return false;

        return (region.Protect & PAGE_READABLE_MASK) != 0;
    }

    private static ProcessModule? FindModule
    (
        string? moduleName
    )
    {
        var process = Process.GetCurrentProcess();

        if (string.IsNullOrWhiteSpace(moduleName))
            return process.MainModule;

        foreach (ProcessModule module in process.Modules)
        {
            if (module.ModuleName is { } name && name.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
            {
                return module;
            }
        }

        throw new McpException($"找不到模块 \"{moduleName}\"。");
    }
}
