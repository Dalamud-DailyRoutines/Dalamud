using System.Reflection;
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
            "对托管对象做读取、写入、方法调用与成员列举。根可以是 service:类型名、裸服务类型名、服务类型名.成员路径，或引用 id。list 对集合一次铺开全部元素（上限 512 个），对其它对象列出字段与属性及其当前值。",
            false
        );
        Add
        (
            collection,
            typeof(FfcsIndexTool),
            nameof(FfcsIndexTool.Run),
            "ffcs_index",
            "查询 FFXIVClientStructs 的类型、符号地址、字段布局与失效签名。symbols 省略 type 时按 filter 跨全部类型搜索符号名；布局会报出内联数组的元素类型与元素个数。",
            true
        );
        Add
        (
            collection,
            typeof(FfcsCallTool),
            nameof(FfcsCallTool.Run),
            "ffcs_call",
            "复用 FFXIVClientStructs 生成的方法，对原生实例调用成员函数。文本实参按目标签名转换，Utf8String* 与 CStringPointer 参数会按各自布局组装。",
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
            true
        );
        Add
        (
            collection,
            typeof(ObserveTool),
            nameof(ObserveTool.Run),
            "observe",
            "安装观察点：内存变化、原生挂钩、托管挂钩与托管事件。",
            false
        );
        Add
        (
            collection,
            typeof(EvidenceTool),
            nameof(EvidenceTool.Run),
            "evidence",
            "按游标拉取观察点产生的证据，并支持长轮询等待。",
            true
        );
        Add
        (
            collection,
            typeof(ControlTool),
            nameof(ControlTool.Run),
            "control",
            "列出线程、挂起与恢复线程。",
            false
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
            "抓取一帧画面并附上坐标基准，可用 region 裁剪出指定区域并等比放大以看清细节。",
            true
        );
        Add
        (
            collection,
            typeof(InputTool),
            nameof(InputTool.Run),
            "input",
            "注入键鼠输入，坐标与 capture 的渲染帧像素一致。需要游戏窗口在前台，默认不切换前台，显式传 activate 才会切换。",
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
        var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static) ?? throw new MissingMethodException(type.FullName, methodName);

        var options = new McpServerToolCreateOptions
        {
            Name        = toolName,
            Description = description,
            ReadOnly    = readOnly
        };

        collection.Add(McpServerTool.Create(method, (object?)null, options));
    }
}
