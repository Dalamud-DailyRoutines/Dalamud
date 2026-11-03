using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Dalamud;

/// <summary>按帧执行输入序列，并可在操作完成后返回截图。</summary>
internal static class InputTool
{
    public enum Operation
    {
        Play, Command
    }

    public enum Target
    {
        Game, Plugin
    }

    public static async Task<IEnumerable<ContentBlock>> Run
    (
        [Description("play 播放 actions；command 执行 Dalamud 斜杠命令。")]
        Operation action,
        [Description("game 为游戏本体；plugin 为主游戏窗口内的 Dalamud 插件界面。只向指定目标注入。")]
        Target target = Target.Plugin,
        [Description("按顺序执行的结构化输入动作，支持 move、click、double_click、drag、scroll、key、text、wait。")]
        InputAction[]? actions = null,
        [Description("capture 返回的 screenshot 编号。提供后，所有鼠标坐标直接使用该截图的图像像素。")]
        string? screenshot = null,
        [Description("command 操作的 Dalamud 斜杠命令，例如 /pdr。")]
        string? command = null,
        [Description("完成后抓取一帧并返回，默认开启。")]   bool           captureAfter = true,
        [Description("后续截图的渲染帧区域，省略为全画面。")] CaptureRegion? region       = null,
        [Description("后续截图最长边，0 为原尺寸，正数允许缩小或放大。")]
        int maxDimension = 1600,
        CancellationToken cancellationToken = default
    )
    {
        string result;

        switch (action)
        {
            case Operation.Play:
                if (actions is null)
                    throw new McpException("play 需要 actions。");

                var frames = await InputSender.Send(actions, target == Target.Plugin, screenshot, cancellationToken).ConfigureAwait(false);
                result = JsonSerializer.Serialize(new { target, actions = actions.Length, frames, injected = true, effectVerified = false });
                break;
            case Operation.Command:
                result = await CommandSender.Send(command, cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new McpException("未知 input 操作。");
        }

        var content = new List<ContentBlock>();

        if (captureAfter)
        {
            try
            {
                var frame = await ScreenCapture.CaptureAsync(maxDimension, region, cancellationToken).ConfigureAwait(false);
                CaptureStore.Add(frame);
                content.Add
                (
                    new TextContentBlock
                        { Text = JsonSerializer.Serialize(new { input = JsonSerializer.Deserialize<JsonElement>(result), capture = CaptureTool.Describe(frame) }) }
                );
                content.Add(ImageContentBlock.FromBytes(frame.Png, "image/png"));
            }
            catch (Exception exception)
            {
                content.Add
                (
                    new TextContentBlock
                        { Text = JsonSerializer.Serialize(new { input = JsonSerializer.Deserialize<JsonElement>(result), captureError = exception.Message }) }
                );
            }
        }
        else
        {
            content.Add(new TextContentBlock { Text = result });
        }

        return content;
    }
}
