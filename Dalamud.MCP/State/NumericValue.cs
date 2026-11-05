using System.Globalization;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>整数保持完整精度，浮点数按其原始数值类型比较。</summary>
internal readonly record struct NumericValue
(
    decimal Integer,
    double  Floating,
    bool    IsFloat
) : IComparable<NumericValue>
{
    public object Value => this.IsFloat ?
                               this.Floating :
                               this.Integer;

    public int CompareTo(NumericValue other) => this.IsFloat ?
                                                    this.Floating.CompareTo(other.Floating) :
                                                    this.Integer.CompareTo(other.Integer);

    public static NumericValue FromInteger(decimal value) => new(value, 0, false);

    public static NumericValue FromFloat(double value) => new(0, value, true);

    public static NumericValue Parse(string text, string valueType)
    {
        var kind = valueType.ToLowerInvariant();

        switch (kind)
        {
            case "float" or "f32" or "single":
                return FromFloat(float.Parse(text, CultureInfo.InvariantCulture));
            case "double" or "f64":
                return FromFloat(double.Parse(text, CultureInfo.InvariantCulture));
            case "bool" when bool.TryParse(text, out var boolean):
                return FromInteger
                (
                    boolean ?
                        1 :
                        0
                );
        }

        var value = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ?
                        ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture) :
                        decimal.Parse(text, CultureInfo.InvariantCulture);
        if (decimal.Truncate(value) != value || value < long.MinValue || value > ulong.MaxValue)
            throw new McpException("整数扫描需要 long 或 ulong 范围内的整数。");

        return FromInteger(value);
    }

    public override string ToString() => this.IsFloat ?
                                             this.Floating.ToString("R", CultureInfo.InvariantCulture) :
                                             this.Integer.ToString(CultureInfo.InvariantCulture);

    public static bool operator <(NumericValue left, NumericValue right) => left.CompareTo(right) < 0;

    public static bool operator >(NumericValue left, NumericValue right) => left.CompareTo(right) > 0;

    public static bool operator <=(NumericValue left, NumericValue right) => left.CompareTo(right) <= 0;

    public static bool operator >=(NumericValue left, NumericValue right) => left.CompareTo(right) >= 0;
}
