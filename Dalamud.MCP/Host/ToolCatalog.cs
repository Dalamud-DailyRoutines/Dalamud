using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace Dalamud;

/// <summary>
/// 把各原语的静态入口注册成 MCP 工具。
/// </summary>
internal static class ToolCatalog
{
    /// <summary>
    /// 创建工具集合。
    /// </summary>
    /// <returns>进程内共享的工具集合。</returns>
    public static McpServerPrimitiveCollection<McpServerTool> Create()
    {
        var collection = new McpServerPrimitiveCollection<McpServerTool>();

        Add
        (
            collection,
            typeof(ServiceListTool),
            nameof(ServiceListTool.Run),
            "service_list",
            "列出 Dalamud 服务类型、类别与当前构造状态。",
            true
        );
        Add
        (
            collection,
            typeof(ObjectAccessTool),
            nameof(ObjectAccessTool.Run),
            "object_access",
            "托管运行时入口。先 service_list 或 types 找目标，再 describe 取得完整成员和方法 id；read、query 支持路径、分页及字段投影；invoke 用方法 id 和 JSON 实参；task 取得异步结果；release 显式释放强引用。describe 不读取属性。操作默认在框架线程执行。",
            false
        );
        Add
        (
            collection,
            typeof(FfcsIndexTool),
            nameof(FfcsIndexTool.Run),
            "ffcs_index",
            "原生类型与符号发现。types 搜索类型；describe 返回方法 id、参数、返回类型及可调用状态；symbols 查看地址与特征码 pattern；layout 查看字段偏移及内联数组布局。调用前使用 describe 消除重载歧义。",
            true
        );
        Add
        (
            collection,
            typeof(FfcsCallTool),
            nameof(FfcsCallTool.Run),
            "ffcs_call",
            "使用 ffcs_index describe 返回的方法 id 在框架线程调用原生方法。JSON 参数区分地址、借用文本、对象引用与 null。借用文本仅在调用期间有效，方法不得保留其指针。",
            false
        );
        Add
        (
            collection,
            typeof(MemReadTool),
            nameof(MemReadTool.Run),
            "mem_read",
            "读取原生内存，支持原始转储与按类型元数据的结构化读取。类型路径支持内联数组下标与 Length，字符串字段会解成文本，读取前校验目标区域是否可读。",
            true
        );
        Add
        (
            collection,
            typeof(MemWriteTool),
            nameof(MemWriteTool.Run),
            "mem_write",
            "写入原生内存，支持原始字节与按类型元数据的字段写入，写入前校验目标区域是否可写。",
            false
        );
        Add
        (
            collection,
            typeof(MemScanTool),
            nameof(MemScanTool.Run),
            "mem_scan",
            "特征码扫描、数值扫描与带会话的收敛过滤。值类型支持 byte、sbyte、short、ushort、int、uint、long、ulong、float、double 与 bool。",
            false
        );
        Add
        (
            collection,
            typeof(ObserveTool),
            nameof(ObserveTool.Run),
            "observe",
            "安装有期限和采样限制的内存、原生方法、托管方法及事件观察点。方法使用 describe 返回的成员 id。结果经 evidence 游标读取，完成后 remove 解除观察。",
            false
        );
        Add
        (
            collection,
            typeof(EvidenceTool),
            nameof(EvidenceTool.Run),
            "evidence",
            "按游标拉取观察点产生的证据，并支持长轮询等待。返回 nextCursor 与证据保留边界；gap 表示存在丢失。clear 会清空全部客户端共享证据。",
            false
        );
        Add
        (
            collection,
            typeof(ControlTool),
            nameof(ControlTool.Run),
            "control",
            "列出进程线程或服务器状态。进程内服务不支持全进程暂停。",
            true
        );
        Add
        (
            collection,
            typeof(DataTool),
            nameof(DataTool.Run),
            "data",
            "读取游戏数据表：表名、行 id、单行内容与列检索。",
            true
        );
        Add
        (
            collection,
            typeof(CaptureTool),
            nameof(CaptureTool.Run),
            "capture",
            "抓取包含插件界面的游戏帧，或按 screenshot 编号裁剪缓存画面。region 为结构化矩形，maxDimension 可缩小或放大。返回 screenshot 坐标引用，后续输入可直接使用图像像素，不必手工换算。",
            true
        );
        Add
        (
            collection,
            typeof(InputTool),
            nameof(InputTool.Run),
            "input",
            "按帧向指定目标播放结构化 actions：game 为游戏本体，plugin 为主窗口内的插件界面。支持点击、双击、拖动、滚动、组合键、插件文本及等待。不会激活游戏窗口或移动桌面光标。使用 screenshot 编号后可直接传图像像素坐标；默认执行后截图。完成表示输入帧已注入，界面效果须依据返回画面判断。command 执行 Dalamud 斜杠命令。",
            false
        );
        Add
        (
            collection,
            typeof(TraceTool),
            nameof(TraceTool.Run),
            "trace",
            "读取调试服务器自身记录的操作流水。",
            true
        );

        return collection;
    }

    private static void Add
    (
        McpServerPrimitiveCollection<McpServerTool> collection,
        Type                                        type,
        string                                      methodName,
        string                                      toolName,
        string                                      description,
        bool                                        readOnly
    )
    {
        try
        {
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static) ?? throw new MissingMethodException(type.FullName, methodName);

            var options = new McpServerToolCreateOptions
            {
                Name        = toolName,
                Description = description,
                ReadOnly    = readOnly,
                SerializerOptions = new JsonSerializerOptions(McpJsonUtilities.DefaultOptions)
                {
                    Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) }
                }
            };

            collection.Add(new MCPInvocationTool(McpServerTool.Create(method, (object?)null, options)));
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException($"创建 MCP 工具“{toolName}”失败：{exception.GetBaseException().Message}", exception);
        }
    }
}
