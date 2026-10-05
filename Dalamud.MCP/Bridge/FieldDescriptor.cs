namespace Dalamud;

/// <summary>
/// 描述一个托管结构字段的名称、偏移、类型与大小。
/// </summary>
internal sealed class FieldDescriptor
{
    /// <summary>
    /// 初始化 <see cref="FieldDescriptor"/> 类的新实例。
    /// </summary>
    /// <param name="name">字段名。</param>
    /// <param name="fieldType">字段类型。</param>
    /// <param name="offset">相对结构起点的字节偏移。</param>
    /// <param name="size">字段占用的字节数。</param>
    public FieldDescriptor
    (
        string name,
        Type   fieldType,
        int    offset,
        int    size
    )
    {
        this.Name      = name;
        this.FieldType = fieldType;
        this.Offset    = offset;
        this.Size      = size;
    }

    /// <summary>
    /// Gets 字段名。
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets 字段类型。
    /// </summary>
    public Type FieldType { get; }

    /// <summary>
    /// Gets 相对结构起点的字节偏移。
    /// </summary>
    public int Offset { get; }

    /// <summary>
    /// Gets 字段占用的字节数。
    /// </summary>
    public int Size { get; }
}
