using System.ComponentModel;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Dalamud.Game;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>按精确成员签名在框架线程调用原生方法。</summary>
internal static class FfcsCallTool
{
    public static async Task<string> Run
    (
        [Description("FFXIVClientStructs 类型全名。")]
        string type,
        [Description("ffcs_index describe 返回的方法 id。")]
        string member,
        [Description("实例地址，静态方法省略。")] string? instance = null,
        [Description("JSON 实参。指针使用 {\"address\":\"0x...\"}，借用文本使用 {\"text\":\"文本\"}，文本内存只在本次调用期间有效。")]
        JsonElement[]? arguments = null,
        int               depth             = 0,
        CancellationToken cancellationToken = default
    )
    {
        var structType   = StructureLayout.FindType(type);
        var rawArguments = arguments ?? [];
        var method       = MemberCatalog.ResolveMethod(structType, member, rawArguments.Length, true);
        var thisPointer = instance is null ?
                              0 :
                              (nint)MemoryAccess.ParseAddress(instance);
        if (!method.IsStatic && (thisPointer == 0 || !MemoryAccess.IsRangeReadable(thisPointer, Math.Max(StructureLayout.GetSize(structType), 1))))
            throw new McpException("实例方法需要可读的完整实例地址。");

        return await Service<Framework>.Get().Run
               (
                   () =>
                   {
                       cancellationToken.ThrowIfCancellationRequested();
                       var result = InteropInvoker.Invoke(method, thisPointer, rawArguments);
                       return JsonSerializer.Serialize
                       (
                           new
                           {
                               type   = structType.FullName,
                               member = MemberCatalog.Identify(method),
                               value  = ValueFormatter.Snapshot(result, depth),
                               thread = "framework"
                           }
                       );
                   },
                   cancellationToken
               ).ConfigureAwait(false);
    }
}
