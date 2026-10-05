using Dalamud.Game;
using Dalamud.Game.Command;
using Dalamud.Utility;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 在框架线程上执行游戏内斜杠命令。
/// </summary>
internal static class CommandSender
{
    /// <summary>
    /// 执行一条斜杠命令。
    /// </summary>
    /// <param name="content">命令文本，需要以 / 开头，例如 /pdr。</param>
    /// <returns>JSON 文本。</returns>
    public static string Send
    (
        string? content
    )
    {
        var text = string.IsNullOrWhiteSpace(content)
                       ? throw new McpException("command 模式需要提供 command，例如 /pdr。")
                       : content.Trim();

        if (!text.StartsWith('/'))
            throw new McpException($"游戏内命令需要以 / 开头，当前为 \"{text}\"。");

        var accepted = false;

        Service<Framework>.Get()
                          .RunOnTick(() => accepted = Service<CommandManager>.Get().ProcessCommand(text))
                          .WaitSafely();

        return "{\"command\":" + ValueFormatter.Format(text, 0) + ",\"accepted\":" + (accepted ? "true" : "false") + "}";
    }
}
