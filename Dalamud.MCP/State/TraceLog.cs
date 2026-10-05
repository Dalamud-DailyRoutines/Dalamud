using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace Dalamud;

/// <summary>
/// 把每一次原生调用、观察点装卸与写操作追加到 jsonl 文件，供崩溃后复盘。
/// </summary>
internal sealed class TraceLog
{
    private const string DIRECTORY_NAME = "dalamud-mcp";
    private const string FILE_NAME      = "trace.jsonl";
    private const long   MAX_FILE_BYTES = 64L * 1024 * 1024;

    private readonly Lock writeLock = new();

    /// <summary>
    /// 初始化 <see cref="TraceLog"/> 类的新实例。
    /// </summary>
    public TraceLog()
    {
        this.FilePath = Path.Combine
        (
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "XIVLauncherCN",
            DIRECTORY_NAME,
            FILE_NAME
        );
    }

    /// <summary>
    /// Gets trace 文件的完整路径。
    /// </summary>
    public string FilePath { get; }

    /// <summary>
    /// 追加一条记录。
    /// </summary>
    /// <param name="category">记录类别。</param>
    /// <param name="message">记录内容。</param>
    /// <param name="elapsedMilliseconds">耗时毫秒数，无意义时传 null。</param>
    public void Write
    (
        string  category,
        string  message,
        double? elapsedMilliseconds = null
    )
    {
        var builder = new StringBuilder(256);
        builder.Append("{\"t\":\"")
               .Append(DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture))
               .Append("\",\"category\":\"")
               .Append(Escape(category))
               .Append("\",\"message\":\"")
               .Append(Escape(message))
               .Append('"');

        if (elapsedMilliseconds.HasValue)
        {
            builder.Append(",\"ms\":")
                   .Append(elapsedMilliseconds.Value.ToString("F3", CultureInfo.InvariantCulture));
        }

        builder.Append("}\n");

        lock (this.writeLock)
        {
            var directory = Path.GetDirectoryName(this.FilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if (File.Exists(this.FilePath) && new FileInfo(this.FilePath).Length > MAX_FILE_BYTES)
                File.Move(this.FilePath, this.FilePath + ".1", true);

            File.AppendAllText(this.FilePath, builder.ToString(), Encoding.UTF8);
        }
    }

    /// <summary>
    /// 读取 trace 文件尾部的若干行。
    /// </summary>
    /// <param name="maxLines">最多返回的行数。</param>
    /// <returns>按时间顺序排列的行。</returns>
    public string[] Tail
    (
        int maxLines
    )
    {
        lock (this.writeLock)
        {
            if (!File.Exists(this.FilePath))
                return [];

            var lines = File.ReadAllLines(this.FilePath, Encoding.UTF8);
            if (lines.Length <= maxLines)
                return lines;

            var result = new string[maxLines];
            Array.Copy(lines, lines.Length - maxLines, result, 0, maxLines);
            return result;
        }
    }

    private static string Escape
    (
        string value
    )
    {
        var builder = new StringBuilder(value.Length + 8);

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

        return builder.ToString();
    }
}
