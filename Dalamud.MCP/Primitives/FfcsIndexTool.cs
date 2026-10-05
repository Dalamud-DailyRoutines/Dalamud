using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using InteropGenerator.Runtime;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// <c>ffcs_index</c> 原语：查询 FFXIVClientStructs 的类型、符号地址、字段布局与失效签名。
/// </summary>
internal static class FfcsIndexTool
{
    private const           string FFCS_ASSEMBLY_PREFIX = "FFXIVClientStructs";
    private static readonly Type   ADDRESS_TYPE         = typeof(Address);

    /// <summary>
    /// 执行查询。
    /// </summary>
    /// <param name="action">操作类型: types、symbols、layout、unresolved、by_addr。</param>
    /// <param name="type">类型全名或简单名，symbols 与 layout 需要。</param>
    /// <param name="filter">按名称做不区分大小写的包含匹配。</param>
    /// <param name="address">by_addr 时给出的地址。</param>
    /// <param name="offset">结果偏移。</param>
    /// <param name="limit">最多返回的条目数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string  action,
        string? type    = null,
        string? filter  = null,
        string? address = null,
        int     offset  = 0,
        int     limit   = 50
    )
    {
        var page = Math.Clamp(limit, 1, 500);
        var skip = Math.Max(offset, 0);

        return action.ToLowerInvariant() switch
        {
            "types"      => ListTypes(filter, skip, page),
            "symbols"    => type is null ? SearchSymbols(filter, skip, page) : ListSymbols(RequireType(type), filter, skip, page),
            "layout"     => ListLayout(RequireType(type), skip, page),
            "unresolved" => ListUnresolved(filter, skip, page),
            "by_addr" => string.IsNullOrWhiteSpace(address)
                             ? throw new McpException("by_addr 需要提供 address。")
                             : FindByAddress((nint)MemoryAccess.ParseAddress(address)),
            _ => throw new McpException($"不支持的操作 \"{action}\"，可用值为 types、symbols、layout、unresolved、by_addr。")
        };
    }

    private static Type RequireType
    (
        string? name
    ) =>
        string.IsNullOrWhiteSpace(name)
            ? throw new McpException("该操作需要提供 type。")
            : StructureLayout.FindType(name);

    private static string ListTypes
    (
        string? filter,
        int     skip,
        int     limit
    )
    {
        var assembly = FindFfcsAssembly();
        if (assembly is null)
            return "{\"error\":\"未找到 FFXIVClientStructs 程序集。\"}";

        Type[] types;

        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException exception)
        {
            types = [.. exception.Types.Where(type => type is not null).Select(type => type!)];
        }

        var candidates = types
                         .Where(type => type.IsValueType                  || type.IsEnum)
                         .Where(type => string.IsNullOrWhiteSpace(filter) || (type.FullName ?? type.Name).Contains(filter, StringComparison.OrdinalIgnoreCase))
                         .OrderBy(type => type.FullName, StringComparer.Ordinal)
                         .ToArray();

        var builder = new StringBuilder(4096);
        builder.Append("{\"total\":").Append(candidates.Length).Append(",\"items\":[");

        var page = candidates.Skip(skip).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var candidate = page[index];
            builder.Append("{\"name\":").Append(ValueFormatter.Format(candidate.Name,                           0));
            builder.Append(",\"fullName\":").Append(ValueFormatter.Format(candidate.FullName ?? candidate.Name, 0));

            if (candidate.IsValueType && !candidate.IsEnum && candidate != typeof(void))
            {
                try
                {
                    builder.Append(",\"size\":").Append(StructureLayout.GetSize(candidate));
                }
                catch (McpException)
                {
                    // ignored
                }
            }

            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string ListSymbols
    (
        Type    type,
        string? filter,
        int     skip,
        int     limit
    )
    {
        var addressClass = type.GetNestedType("Addresses", BindingFlags.Public | BindingFlags.NonPublic);
        if (addressClass is null)
            throw new McpException($"{type.Name} 内没有 Addresses 嵌套类型，说明该类型没有登记任何签名。");

        var symbols = addressClass
                      .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.NonPublic)
                      .Where(field => ADDRESS_TYPE.IsAssignableFrom(field.FieldType))
                      .Where(field => string.IsNullOrWhiteSpace(filter) || field.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                      .Select(field => (Field: field, Value: field.GetValue(null) as Address))
                      .Where(entry => entry.Value is not null)
                      .ToArray();

        var builder = new StringBuilder(2048);
        builder.Append("{\"type\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
        builder.Append(",\"total\":").Append(symbols.Length).Append(",\"items\":[");

        var page = symbols.Skip(skip).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var entry = page[index];
            var value = entry.Value!;
            builder.Append("{\"name\":").Append(ValueFormatter.Format(entry.Field.Name, 0));
            builder.Append(",\"address\":").Append(ValueFormatter.Format(value.Value,   0));
            builder.Append(",\"resolved\":").Append(value.Value == 0 ? "false" : "true");
            builder.Append(",\"signature\":").Append(ValueFormatter.Format(value.String, 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string SearchSymbols
    (
        string? filter,
        int     skip,
        int     limit
    )
    {
        var keyword = filter?.Trim();
        if (string.IsNullOrEmpty(keyword))
            throw new McpException("按名称搜索符号需要提供 filter；给出 type 则列出该类型的全部符号。");

        var assembly = FindFfcsAssembly() ?? throw new McpException("未找到 FFXIVClientStructs 程序集。");

        var matches = new List<(string TypeName, string Name, Address Value)>();

        foreach (var type in assembly.GetTypes())
        {
            var addressClass = type.GetNestedType("Addresses", BindingFlags.Public | BindingFlags.NonPublic);
            if (addressClass is null)
                continue;

            foreach (var field in addressClass.GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.NonPublic))
            {
                if (!ADDRESS_TYPE.IsAssignableFrom(field.FieldType) || !field.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (field.GetValue(null) is Address address)
                    matches.Add((type.FullName ?? type.Name, field.Name, address));
            }
        }

        var builder = new StringBuilder(2048);
        builder.Append("{\"filter\":").Append(ValueFormatter.Format(keyword, 0));
        builder.Append(",\"total\":").Append(matches.Count).Append(",\"items\":[");

        var page = matches.Skip(skip).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var entry = page[index];
            builder.Append("{\"type\":").Append(ValueFormatter.Format(entry.TypeName,       0));
            builder.Append(",\"name\":").Append(ValueFormatter.Format(entry.Name,           0));
            builder.Append(",\"address\":").Append(ValueFormatter.Format(entry.Value.Value, 0));
            builder.Append(",\"resolved\":").Append(entry.Value.Value == 0 ? "false" : "true");
            builder.Append(",\"signature\":").Append(ValueFormatter.Format(entry.Value.String, 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string ListLayout
    (
        Type type,
        int  skip,
        int  limit
    )
    {
        if (type.IsEnum)
            return RenderEnum(type);

        var fields = StructureLayout.GetFields(type);

        var builder = new StringBuilder(2048);
        builder.Append("{\"type\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));

        var typeSize = StructureLayout.GetSize(type);
        builder.Append(",\"size\":").Append(typeSize < 0 ? "null" : typeSize.ToString(CultureInfo.InvariantCulture));
        builder.Append(",\"total\":").Append(fields.Count).Append(",\"fields\":[");

        var page = fields.Skip(skip).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var field = page[index];
            builder.Append("{\"name\":").Append(ValueFormatter.Format(field.Name, 0));
            builder.Append(",\"offset\":").Append(field.Offset);
            builder.Append(",\"size\":").Append(field.Size < 0 ? "null" : field.Size.ToString(CultureInfo.InvariantCulture));
            builder.Append(",\"type\":").Append(ValueFormatter.Format(field.FieldType.FullName ?? field.FieldType.Name, 0));

            if (StructureLayout.TryGetInlineArray(field.FieldType) is { } inlineArray)
            {
                builder.Append(",\"elementType\":").Append(ValueFormatter.Format(inlineArray.ElementType.FullName ?? inlineArray.ElementType.Name, 0));
                builder.Append(",\"elementCount\":").Append(inlineArray.Count);
            }

            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string RenderEnum
    (
        Type type
    )
    {
        var underlying = Enum.GetUnderlyingType(type);
        var names      = Enum.GetNames(type);
        var builder    = new StringBuilder(1024);

        builder.Append("{\"type\":").Append(ValueFormatter.Format(type.FullName ?? type.Name, 0));
        builder.Append(",\"kind\":\"enum\"");
        builder.Append(",\"underlyingType\":").Append(ValueFormatter.Format(underlying.Name, 0));
        builder.Append(",\"total\":").Append(names.Length).Append(",\"values\":[");

        for (var index = 0; index < names.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var value = Convert.ChangeType(Enum.Parse(type, names[index]), underlying, CultureInfo.InvariantCulture);

            builder.Append("{\"name\":").Append(ValueFormatter.Format(names[index], 0));
            builder.Append(",\"value\":").Append(ValueFormatter.Format(value, 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string ListUnresolved
    (
        string? filter,
        int     skip,
        int     limit
    )
    {
        var unresolved = Resolver.GetInstance.Addresses
                                 .Where(entry => entry.Value == 0)
                                 .Where(entry => string.IsNullOrWhiteSpace(filter) || entry.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                                 .OrderBy(entry => entry.Name, StringComparer.Ordinal)
                                 .ToArray();

        var builder = new StringBuilder(2048);
        builder.Append("{\"totalTracked\":").Append(Resolver.GetInstance.Addresses.Count);
        builder.Append(",\"totalUnresolved\":").Append(unresolved.Length).Append(",\"items\":[");

        var page = unresolved.Skip(skip).Take(limit).ToArray();

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var entry = page[index];
            builder.Append("{\"name\":").Append(ValueFormatter.Format(entry.Name,        0));
            builder.Append(",\"signature\":").Append(ValueFormatter.Format(entry.String, 0));
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string FindByAddress
    (
        nint address
    )
    {
        var candidates = Resolver.GetInstance.Addresses
                                 .Where(entry => entry.Value != 0)
                                 .Select(entry => (entry, distance: Distance(entry.Value, address)))
                                 .OrderBy(item => item.distance)
                                 .Take(5)
                                 .ToArray();

        var builder = new StringBuilder(1024);
        builder.Append("{\"address\":\"").Append(ToString(address)).Append('"');

        var module = Process.GetCurrentProcess().MainModule;

        if (module is not null)
        {
            var start = module.BaseAddress;
            var end   = start + module.ModuleMemorySize;
            builder.Append(",\"module\":").Append(ValueFormatter.Format(module.ModuleName, 0));
            builder.Append(",\"inModule\":").Append(address >= start && address < end ? "true" : "false");

            if (address >= start && address < end)
                builder.Append(",\"rva\":\"").Append(ToString(address - start)).Append('"');
        }

        builder.Append(",\"nearest\":[");

        for (var index = 0; index < candidates.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            builder.Append("{\"name\":").Append(ValueFormatter.Format(candidates[index].entry.Name, 0));
            builder.Append(",\"address\":\"").Append(ToString(candidates[index].entry.Value)).Append('"');
            builder.Append(",\"distance\":").Append(candidates[index].distance);
            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static Assembly? FindFfcsAssembly() =>
        AppDomain.CurrentDomain.GetAssemblies()
                 .Where(assembly => !assembly.IsDynamic)
                 .FirstOrDefault(assembly => assembly.GetName().Name?.StartsWith(FFCS_ASSEMBLY_PREFIX, StringComparison.Ordinal) == true);

    private static long Distance
    (
        nint left,
        nint right
    ) =>
        left > right ? left - right : right - left;

    private static string ToString
    (
        nint address
    ) =>
        "0x" + ((long)address).ToString("x", CultureInfo.InvariantCulture);
}
