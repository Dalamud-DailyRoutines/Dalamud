using System.Globalization;
using System.Text.Json;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>转换显式 JSON 值、对象引用与原生地址。</summary>
internal static class RuntimeArguments
{
    private static readonly JsonSerializerOptions Options = new() { IncludeFields = true };

    public static object? Bind(JsonElement value, Type targetType)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Null:
                return targetType.IsValueType && Nullable.GetUnderlyingType(targetType) is null ?
                           throw new McpException($"{targetType.Name} 不接受 null。") :
                           null;
        }

        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("ref", out var reference))
        {
            var instance = MCPRuntime.References.GetObject(reference.GetString() ?? string.Empty);
            return targetType.IsInstanceOfType(instance) ?
                       instance :
                       throw new McpException($"引用对象 {instance.GetType().FullName} 不能作为 {targetType.FullName} 参数。");
        }

        var type = Nullable.GetUnderlyingType(targetType) ?? targetType;
        if (type.IsByRef || type.IsByRefLike || type.IsPointer || type.ContainsGenericParameters)
            throw new McpException($"不支持参数类型 {targetType}。");

        var text = value.ValueKind == JsonValueKind.String ?
                       value.GetString()! :
                       value.GetRawText();
        if (type == typeof(nint))
            return (nint)MemoryAccess.ParseAddress(text);

        if (type == typeof(nuint))
            return (nuint)(ulong)MemoryAccess.ParseAddress(text);

        if (type.IsEnum)
            return Enum.Parse(type, text, true);

        if (type == typeof(string))
            return value.ValueKind == JsonValueKind.String ?
                       value.GetString() :
                       throw new McpException("字符串参数必须使用 JSON 字符串。");

        if (type.IsPrimitive || type == typeof(decimal))
            return Convert.ChangeType(text, type, CultureInfo.InvariantCulture);

        return type.IsValueType ?
                   value.Deserialize(type, Options) :
                   throw new McpException($"{type.FullName} 需要使用对象引用参数。");
    }
}
