using System.Linq;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    /// <param name="filePath">日志路径，省略时使用运行时默认路径。</param>
    public TraceLog(string? filePath = null) => this.FilePath = filePath ??
                                                                Path.Combine
                                                                (
                                                                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                                                    "XIVLauncherCN",
                                                                    DIRECTORY_NAME,
                                                                    FILE_NAME
                                                                );

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
        var line = JsonSerializer.Serialize
                   (
                       new
                       {
                           t = DateTimeOffset.UtcNow,
                           category,
                           message,
                           ms = elapsedMilliseconds
                       }
                   ) +
                   "\n";

        lock (this.writeLock)
        {
            var directory = Path.GetDirectoryName(this.FilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if (File.Exists(this.FilePath) && new FileInfo(this.FilePath).Length > MAX_FILE_BYTES)
                File.Move(this.FilePath, this.FilePath + ".1", true);

            File.AppendAllText(this.FilePath, line, new UTF8Encoding(false));
        }
    }

    /// <summary>
    /// 筛选日志并按行号向前分页，限制返回的 JSON 字符数。
    /// </summary>
    /// <param name="maxLines">最多返回的行数。</param>
    /// <param name="filter">内容筛选条件。</param>
    /// <param name="before">只读取此行号之前的记录，零表示从最新记录开始。</param>
    /// <param name="maxCharacters">返回的 JSON 字符数上限。</param>
    /// <returns>包含记录与分页游标的 JSON。</returns>
    public string Tail
    (
        int     maxLines,
        string? filter,
        int     before,
        int     maxCharacters
    )
    {
        lock (this.writeLock)
        {
            var matches       = new Queue<(int Number, string Text)>();
            var lineNumber    = 0;
            var matchingCount = 0;

            if (File.Exists(this.FilePath))
            {
                foreach (var line in File.ReadLines(this.FilePath, Encoding.UTF8))
                {
                    lineNumber++;
                    if (before > 0 && lineNumber >= before)
                        break;

                    if (!string.IsNullOrWhiteSpace(filter) && !line.Contains(filter, StringComparison.OrdinalIgnoreCase))
                        continue;

                    matchingCount++;
                    matches.Enqueue((lineNumber, line));
                    if (matches.Count > maxLines)
                        matches.Dequeue();
                }
            }

            var lines = new JsonArray();
            var response = new JsonObject
            {
                ["file"]       = this.FilePath,
                ["lines"]      = lines,
                ["hasMore"]    = false,
                ["nextBefore"] = null,
                ["truncated"]  = false
            };
            var remaining    = maxCharacters - response.ToJsonString().Length - 128;
            var recordBudget = Math.Min(2048, remaining - 64);
            var oldest       = 0;

            foreach (var match in matches.Reverse())
            {
                JsonNode record;

                if (match.Text.Length > recordBudget)
                {
                    record = new JsonObject
                    {
                        ["line"]               = match.Number,
                        ["truncated"]          = true,
                        ["originalCharacters"] = match.Text.Length,
                        ["preview"]            = match.Text[..Math.Min(match.Text.Length, (recordBudget - 128) / 6)]
                    };
                }
                else
                {
                    record         = JsonNode.Parse(match.Text)!;
                    record["line"] = match.Number;
                }

                var size = record.ToJsonString().Length + 1;
                if (size > remaining)
                    break;

                lines.Insert(0, record);
                remaining -= size;
                oldest    =  match.Number;
                if (match.Text.Length > recordBudget)
                    response["truncated"] = true;
            }

            var hasMore = matchingCount > lines.Count;
            response["hasMore"] = hasMore;
            if (hasMore)
                response["nextBefore"] = oldest;

            return response.ToJsonString();
        }
    }
}
