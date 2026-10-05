using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Dalamud;

/// <summary>
/// 把任意托管值格式化成便于模型阅读的 JSON 文本。
/// </summary>
internal static class ValueFormatter
{
    private const int MAX_COLLECTION_ITEMS = 256;

    /// <summary>
    /// 格式化一个值。
    /// </summary>
    /// <param name="value">要格式化的值。</param>
    /// <param name="depth">引用类型向下展开的层数。</param>
    /// <returns>JSON 文本。</returns>
    public static string Format
    (
        object? value,
        int     depth
    )
    {
        var builder = new StringBuilder(256);
        Write(builder, value, depth, []);
        return builder.ToString();
    }

    private static void Write
    (
        StringBuilder   builder,
        object?         value,
        int             depth,
        HashSet<object> visited
    )
    {
        if (value is null)
        {
            builder.Append("null");
            return;
        }

        switch (value)
        {
            case string text:
                WriteString(builder, text);
                return;
            case bool flag:
                builder.Append(flag ? "true" : "false");
                return;
            case char character:
                WriteString(builder, character.ToString());
                return;
            case IntPtr intPtr:
                WriteString(builder, FormatPointer(intPtr.ToInt64()));
                return;
            case UIntPtr unsignedIntPtr:
                WriteString(builder, FormatPointer((long)unsignedIntPtr.ToUInt64()));
                return;
            case Type type:
                WriteString(builder, type.FullName ?? type.Name);
                return;
            case Enum enumValue:
                WriteString(builder, enumValue.ToString());
                return;
            case DateTime time:
                WriteString(builder, time.ToString("O", CultureInfo.InvariantCulture));
                return;
            case DateTimeOffset offset:
                WriteString(builder, offset.ToString("O", CultureInfo.InvariantCulture));
                return;
            case TimeSpan span:
                WriteString(builder, span.ToString("c", CultureInfo.InvariantCulture));
                return;
            case Guid identifier:
                WriteString(builder, identifier.ToString("D"));
                return;
            case Task task:
                WriteString(builder, $"Task:{task.Status}");
                return;
        }

        var valueType = value.GetType();

        if (valueType.IsPrimitive || value is decimal)
        {
            builder.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
            return;
        }

        switch (value)
        {
            case IDictionary dictionary:
                WriteDictionary(builder, dictionary, depth, visited);
                return;

            case IEnumerable enumerable and not string:
                WriteEnumerable(builder, enumerable, depth, visited);
                return;

            default:
                WriteObject(builder, value, valueType, depth, visited);
                return;
        }
    }

    private static void WriteDictionary
    (
        StringBuilder   builder,
        IDictionary     dictionary,
        int             depth,
        HashSet<object> visited
    )
    {
        if (!visited.Add(dictionary))
        {
            WriteString(builder, "<循环引用>");
            return;
        }

        try
        {
            builder.Append('{');
            var written   = 0;
            var truncated = false;

            foreach (DictionaryEntry entry in dictionary)
            {
                if (written >= MAX_COLLECTION_ITEMS)
                {
                    truncated = true;
                    break;
                }

                if (written > 0)
                    builder.Append(',');

                WriteString(builder, Convert.ToString(entry.Key, CultureInfo.InvariantCulture) ?? "null");
                builder.Append(':');
                Write(builder, entry.Value, depth - 1, visited);
                written++;
            }

            if (truncated)
                builder.Append(",\"__truncated__\":true");

            builder.Append('}');
        }
        finally
        {
            visited.Remove(dictionary);
        }
    }

    private static void WriteEnumerable
    (
        StringBuilder   builder,
        IEnumerable     enumerable,
        int             depth,
        HashSet<object> visited
    )
    {
        if (!visited.Add(enumerable))
        {
            WriteString(builder, "<循环引用>");
            return;
        }

        try
        {
            builder.Append('[');
            var written   = 0;
            var truncated = false;

            foreach (var item in enumerable)
            {
                if (written >= MAX_COLLECTION_ITEMS)
                {
                    truncated = true;
                    break;
                }

                if (written > 0)
                    builder.Append(',');

                Write(builder, item, depth - 1, visited);
                written++;
            }

            if (truncated)
                builder.Append(written > 0 ? ",\"__truncated__\"" : "\"__truncated__\"");

            builder.Append(']');
        }
        finally
        {
            visited.Remove(enumerable);
        }
    }

    private static void WriteObject
    (
        StringBuilder   builder,
        object          value,
        Type            valueType,
        int             depth,
        HashSet<object> visited
    )
    {
        var typeName = valueType.FullName ?? valueType.Name;

        if (depth <= 0)
        {
            builder.Append("{\"__type__\":");
            WriteString(builder, typeName);
            builder.Append('}');
            return;
        }

        if (!visited.Add(value))
        {
            WriteString(builder, "<循环引用>");
            return;
        }

        try
        {
            builder.Append("{\"__type__\":");
            WriteString(builder, typeName);
            builder.Append(",\"members\":{");

            var written   = 0;
            var truncated = false;

            foreach (var member in EnumerateMembers(valueType))
            {
                if (written >= MAX_COLLECTION_ITEMS)
                {
                    truncated = true;
                    break;
                }

                object? memberValue;

                try
                {
                    memberValue = member switch
                    {
                        FieldInfo field                                                      => field.GetValue(value),
                        PropertyInfo property when property.GetIndexParameters().Length == 0 => property.GetValue(value),
                        _                                                                    => null
                    };
                }
                catch (Exception exception)
                {
                    memberValue = $"<读取失败: {exception.GetType().Name}>";
                }

                if (written > 0)
                    builder.Append(',');

                WriteString(builder, member.Name);
                builder.Append(':');
                Write(builder, memberValue, depth - 1, visited);
                written++;
            }

            if (truncated)
                builder.Append(",\"__truncated__\":true");

            builder.Append("}}");
        }
        finally
        {
            visited.Remove(value);
        }
    }

    private static IEnumerable<MemberInfo> EnumerateMembers
    (
        Type type
    )
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly;

        for (var current = type; current is not null && current != typeof(object); current = current.BaseType)
        {
            foreach (var field in current.GetFields(flags))
                yield return field;

            foreach (var property in current.GetProperties(flags))
            {
                if (property.GetIndexParameters().Length == 0 && property.CanRead)
                    yield return property;
            }
        }
    }

    private static string FormatPointer
    (
        long address
    ) =>
        "0x" + address.ToString("X", CultureInfo.InvariantCulture);

    private static void WriteString
    (
        StringBuilder builder,
        string        value
    )
    {
        builder.Append('"');

        foreach (var character in value)
        {
            switch (character)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append(@"\\");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (character < ' ')
                        builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        builder.Append(character);
                    break;
            }
        }

        builder.Append('"');
    }
}
