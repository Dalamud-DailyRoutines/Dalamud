using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 通过 <see cref="ServiceManager"/> 的类型清单与 <see cref="Service{T}"/> 的反射调用解析服务实例。
/// </summary>
internal static class ServiceResolver
{
    /// <summary>
    /// 枚举全部具体服务类型。
    /// </summary>
    /// <returns>服务类型序列。</returns>
    public static IEnumerable<Type> EnumerateServiceTypes() =>
        ServiceManager.GetConcreteServiceTypes().OrderBy(type => type.FullName, StringComparer.Ordinal);

    /// <summary>
    /// 按类型名解析服务类型。
    /// </summary>
    /// <param name="name">类型全名或简单名。</param>
    /// <returns>服务类型。</returns>
    public static Type FindServiceType
    (
        string name
    )
    {
        var matches = EnumerateServiceTypes()
                      .Where
                      (type => string.Equals
                                   (type.FullName, name, StringComparison.Ordinal)                       ||
                               string.Equals(type.Name,     name,              StringComparison.Ordinal) ||
                               string.Equals(type.FullName, "Dalamud." + name, StringComparison.Ordinal)
                      )
                      .ToArray();

        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new McpException($"找不到服务类型 \"{name}\"。{SuggestServiceNames(name)}"),
            _ => throw new McpException($"服务类型 \"{name}\" 匹配到多个结果: {string.Join(", ", matches.Select(type => type.Name))}")
        };
    }

    /// <summary>
    /// 取回服务实例，必要时等待其构造完成。
    /// </summary>
    /// <param name="serviceType">服务类型。</param>
    /// <returns>服务实例。</returns>
    public static object Get
    (
        Type serviceType
    )
    {
        var wrapper = typeof(Service<>).MakeGenericType(serviceType);
        var method = wrapper.GetMethod
                         (nameof(Service<>.Get), BindingFlags.Public | BindingFlags.Static) ??
                     throw new McpException($"服务 {serviceType.Name} 没有可用的 Get 方法。");

        try
        {
            return method.Invoke(null, null) ?? throw new McpException($"服务 {serviceType.Name} 返回了空实例。");
        }
        catch (TargetInvocationException exception)
        {
            throw new McpException($"服务 {serviceType.Name} 不可用: {exception.InnerException?.Message}");
        }
    }

    /// <summary>
    /// 尝试取回服务实例，未构造完成时返回 null。
    /// </summary>
    /// <param name="serviceType">服务类型。</param>
    /// <returns>服务实例或 null。</returns>
    public static object? GetOrNull
    (
        Type serviceType
    )
    {
        var wrapper = typeof(Service<>).MakeGenericType(serviceType);
        var method  = wrapper.GetMethod(nameof(Service<>.GetNullable), BindingFlags.Public | BindingFlags.Static);
        if (method is null)
            return null;

        try
        {
            return method.Invoke(null, [Type.Missing]);
        }
        catch (TargetInvocationException)
        {
            return null;
        }
    }

    private static string SuggestServiceNames
    (
        string name
    )
    {
        var fragments = name.Split([' ', '.', '_', '-', ':', '/'], StringSplitOptions.RemoveEmptyEntries);

        var matches = EnumerateServiceTypes()
                      .Where(type => fragments.Any(fragment => type.Name.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
                      .Select(type => type.Name)
                      .Distinct(StringComparer.Ordinal)
                      .Take(12)
                      .ToArray();

        return matches.Length == 0
                   ? "名称中不包含这些片段，可用 service_list 查看全部服务名。"
                   : $"名称含相关片段的候选: {string.Join(", ", matches)}";
    }
}
