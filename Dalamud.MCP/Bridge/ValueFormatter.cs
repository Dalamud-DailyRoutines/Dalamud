using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Dalamud;

/// <summary>使用共享节点预算展开值，属性只通过显式路径读取。</summary>
internal static class ValueFormatter
{
    public static string Format(object? value, int depth) => Snapshot(value, depth)?.ToJsonString() ?? "null";

    public static JsonNode? Snapshot(object? value, int depth = 0)
    {
        var          budget  = 256;
        List<object> visited = [];
        return Write(value, Math.Clamp(depth, 0, 4), visited, ref budget);
    }

    private static JsonNode? Write(object? value, int depth, List<object> visited, ref int budget)
    {
        if (value is null)
            return null;

        if (--budget < 0)
            return new JsonObject { ["truncated"] = true };

        var type = value.GetType();

        switch (value)
        {
            case IntPtr pointer:
                return JsonValue.Create("0x" + pointer.ToInt64().ToString("X", CultureInfo.InvariantCulture));
            case UIntPtr pointer:
                return JsonValue.Create("0x" + pointer.ToUInt64().ToString("X", CultureInfo.InvariantCulture));
            case Type reflectedType:
                return JsonValue.Create(reflectedType.FullName);
            case Enum enumeration:
                return JsonValue.Create(enumeration.ToString());
            case string text:
                return JsonValue.Create
                (
                    text.Length <= 8192 ?
                        text :
                        text[..8192]
                );
            case float number when !float.IsFinite(number):
                return JsonValue.Create(number.ToString(CultureInfo.InvariantCulture));
            case double number when !double.IsFinite(number):
                return JsonValue.Create(number.ToString(CultureInfo.InvariantCulture));
        }

        if (type.IsPrimitive || value is decimal or DateTime or DateTimeOffset or TimeSpan or Guid)
            return JsonSerializer.SerializeToNode(value, type);

        var result = new JsonObject { ["type"] = type.FullName };
        if (!type.IsValueType)
            result["ref"] = MCPRuntime.References.TrackObject(value);

        switch (value)
        {
            case Task task:
                result["status"]    = task.Status.ToString();
                result["completed"] = task.IsCompleted;
                return result;
            case ICollection collection:
                result["count"] = collection.Count;
                break;
        }

        if (depth <= 0)
            return result;

        if (visited.Exists(ancestor => ReferenceEquals(ancestor, value)))
        {
            result["cycle"] = true;
            return result;
        }

        visited.Add(value);

        try
        {
            if (value is IEnumerable enumerable)
            {
                var items = new JsonArray();

                foreach (var item in enumerable)
                {
                    if (items.Count >= 32 || budget <= 0)
                    {
                        result["truncated"] = true;
                        break;
                    }

                    items.Add(Write(item, depth - 1, visited, ref budget));
                }

                result["items"] = items;
                return result;
            }

            var fields = new JsonObject();

            foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.Public))
            {
                if (fields.Count >= 32 || budget <= 0)
                {
                    result["truncated"] = true;
                    break;
                }

                try
                {
                    fields[field.Name] = Write(field.GetValue(value), depth - 1, visited, ref budget);
                }
                catch (Exception exception)
                {
                    fields[field.Name] = new JsonObject { ["error"] = exception.GetBaseException().Message };
                }
            }

            result["fields"] = fields;
            return result;
        }
        finally
        {
            visited.RemoveAt(visited.Count - 1);
        }
    }
}
