using System.Linq;
using System.Text;

namespace Dalamud;

/// <summary>
/// <c>service_list</c> 原语：列出 Dalamud 服务类型、类别与当前构造状态。
/// </summary>
internal static class ServiceListTool
{
    /// <summary>
    /// 执行查询。
    /// </summary>
    /// <param name="filter">按类型全名或简单名做不区分大小写的包含匹配。</param>
    /// <param name="includeState">是否附带当前构造状态。</param>
    /// <param name="offset">结果偏移。</param>
    /// <param name="limit">最多返回的条目数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Run
    (
        string? filter       = null,
        bool    includeState = true,
        int     offset       = 0,
        int     limit        = 100
    )
    {
        var types = ServiceResolver.EnumerateServiceTypes();

        if (!string.IsNullOrWhiteSpace(filter))
        {
            types = types.Where(type => (type.FullName ?? type.Name).Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        var all  = types.ToArray();
        var page = all.Skip(Math.Max(offset, 0)).Take(Math.Clamp(limit, 1, 500)).ToArray();

        var builder = new StringBuilder(1024);
        builder.Append("{\"total\":").Append(all.Length).Append(",\"offset\":").Append(Math.Max(offset, 0));
        builder.Append(",\"items\":[");

        for (var index = 0; index < page.Length; index++)
        {
            if (index > 0)
                builder.Append(',');

            var type = page[index];
            builder.Append("{\"name\":\"").Append(Escape(type.Name)).Append('"');
            builder.Append(",\"fullName\":\"").Append(Escape(type.FullName ?? type.Name)).Append('"');
            builder.Append(",\"kind\":\"").Append(Escape(type.GetServiceKind().ToString())).Append('"');

            if (includeState)
            {
                var instance = ServiceResolver.GetOrNull(type);
                builder.Append(",\"constructed\":").Append(instance is null ? "false" : "true");
                if (instance is not null)
                    builder.Append(",\"ref\":\"").Append(Escape(MCPRuntime.References.TrackObject(instance))).Append('"');
            }

            builder.Append('}');
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static string Escape
    (
        string value
    ) => value.Replace(@"\", @"\\", StringComparison.Ordinal)
              .Replace("\"", "\\\"", StringComparison.Ordinal);
}
