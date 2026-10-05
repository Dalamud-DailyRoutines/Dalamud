using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using FFXIVClientStructs.FFXIV.Client.System.String;
using InteropGenerator.Runtime;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 运行时调用器签名：接受 this 指针与已转换的参数，返回调用结果。
/// </summary>
/// <param name="thisPointer">结构体实例指针，静态方法忽略该值。</param>
/// <param name="arguments">已按目标签名转换的参数。</param>
/// <returns>调用结果，void 方法返回 null。</returns>
internal delegate object? InteropInvocation
(
    nint      thisPointer,
    object?[] arguments
);

/// <summary>
/// 通过动态 IL 复用 FFXIVClientStructs 生成的方法体，把原生指针当作 this 传进去。
/// </summary>
internal static unsafe class InteropInvoker
{
    private static readonly MethodInfo AS_REF_DEFINITION = typeof(Unsafe)
                                                           .GetMethods(BindingFlags.Public | BindingFlags.Static)
                                                           .First
                                                           (method => method.Name == nameof(Unsafe.AsRef)          &&
                                                                      method.IsGenericMethodDefinition             &&
                                                                      method.GetParameters().Length           == 1 &&
                                                                      method.GetParameters()[0].ParameterType == typeof(void*)
                                                           );

    private static readonly Lock                                      CACHE_LOCK = new();
    private static readonly Dictionary<MethodInfo, InteropInvocation> CACHE      = [];

    /// <summary>
    /// 调用目标方法。
    /// </summary>
    /// <param name="method">目标方法，通常是生成的结构体实例方法。</param>
    /// <param name="thisPointer">结构体实例指针。</param>
    /// <param name="rawArguments">以文本给出的实参。</param>
    /// <returns>调用结果。</returns>
    public static object? Invoke
    (
        MethodInfo method,
        nint       thisPointer,
        string[]   rawArguments
    )
    {
        var parameters = method.GetParameters();

        if (parameters.Length != rawArguments.Length)
        {
            throw new McpException
            (
                $"{method.DeclaringType?.Name}.{method.Name} 需要 {parameters.Length} 个参数，实际给出 {rawArguments.Length} 个。"
            );
        }

        var converted = new object?[parameters.Length];
        for (var index = 0; index < parameters.Length; index++)
            converted[index] = ConvertArgument(rawArguments[index], parameters[index].ParameterType);

        return GetInvoker(method)(thisPointer, converted);
    }

    /// <summary>
    /// 把文本转换成目标参数类型。文本形式的 <c>Utf8String*</c> 会按 Utf8String 布局在新分配的内存里组装。
    /// </summary>
    /// <param name="raw">文本形式的值。</param>
    /// <param name="targetType">目标类型。</param>
    /// <returns>转换后的值。</returns>
    public static object? ConvertArgument
    (
        string raw,
        Type   targetType
    )
    {
        if (targetType == typeof(string))
            return raw;

        if (targetType.IsPointer)
        {
            var pointedTo = targetType.GetElementType()!;

            if (pointedTo == typeof(Utf8String))
                return checked((IntPtr)AllocUtf8String(raw));

            if (pointedTo == typeof(byte) && LooksLikeText(raw))
                return checked((IntPtr)AllocUtf8Bytes(raw));

            return checked((IntPtr)MemoryAccess.ParseAddress(raw));
        }

        if (targetType == typeof(CStringPointer))
            return (CStringPointer)AllocUtf8Bytes(raw);

        var underlying = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (underlying == typeof(nint) || underlying == typeof(IntPtr))
            return checked((IntPtr)MemoryAccess.ParseAddress(raw));

        if (underlying == typeof(nuint) || underlying == typeof(UIntPtr))
            return checked((UIntPtr)(ulong)MemoryAccess.ParseAddress(raw));

        if (underlying == typeof(bool))
            return bool.Parse(raw);

        if (underlying.IsEnum)
            return Enum.Parse(underlying, raw, true);

        if (underlying == typeof(char))
            return raw.Length > 0 ? raw[0] : throw new McpException("无法把空字符串转换为 char。");

        return underlying.IsPrimitive
                   ? Convert.ChangeType(raw, underlying, CultureInfo.InvariantCulture)
                   : throw new McpException($"暂不支持把文本转换为 {targetType.Name}。");
    }

    private static byte* AllocUtf8Bytes
    (
        string text
    )
    {
        var bytes  = Encoding.UTF8.GetBytes(text);
        var memory = (byte*)Marshal.AllocHGlobal(bytes.Length + 1);

        for (var index = 0; index < bytes.Length; index++)
            memory[index] = bytes[index];

        memory[bytes.Length] = 0;
        return memory;
    }

    private static Utf8String* AllocUtf8String
    (
        string text
    )
    {
        var size   = StructureLayout.GetSize(typeof(Utf8String));
        var bytes  = Encoding.UTF8.GetBytes(text);
        var memory = (byte*)Marshal.AllocHGlobal(size);

        for (var index = 0; index < size; index++)
            memory[index] = 0;

        var stringPointer = StructureLayout.FindField(typeof(Utf8String), "StringPtr");
        var bufferSize    = StructureLayout.FindField(typeof(Utf8String), "BufSize");
        var bufferUsed    = StructureLayout.FindField(typeof(Utf8String), "BufUsed");
        var stringLength  = StructureLayout.FindField(typeof(Utf8String), "StringLength");
        var isEmpty       = StructureLayout.FindField(typeof(Utf8String), "IsEmpty");
        var useInline     = StructureLayout.FindField(typeof(Utf8String), "IsUsingInlineBuffer");
        var inlineBuffer  = StructureLayout.FindField(typeof(Utf8String), "_inlineBuffer");

        var bufferCapacity = inlineBuffer.Size;

        if (bytes.Length + 1 > bufferCapacity)
            throw new McpException($"文本长度 {bytes.Length} 超过内联缓冲 {bufferCapacity} 字节，暂不支持更长的实参。");

        for (var index = 0; index < bytes.Length; index++)
            *(memory + inlineBuffer.Offset + index) = bytes[index];

        *(memory + inlineBuffer.Offset + bytes.Length) = 0;

        *(nint*)(memory + stringPointer.Offset) = (nint)(memory + inlineBuffer.Offset);
        *(long*)(memory + bufferSize.Offset)    = bufferCapacity;
        *(long*)(memory + bufferUsed.Offset)    = bytes.Length + 1L;
        *(long*)(memory + stringLength.Offset)  = bytes.Length;
        *(memory + isEmpty.Offset)              = bytes.Length == 0 ? (byte)1 : (byte)0;
        *(memory + useInline.Offset)            = 1;

        return (Utf8String*)memory;
    }

    private static bool LooksLikeText
    (
        string raw
    )
    {
        var text = raw.Trim();

        if (text.Length == 0)
            return false;

        return !(text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && long.TryParse
        (
            text[2..],
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture,
            out _
        ));
    }

    private static InteropInvocation GetInvoker
    (
        MethodInfo method
    )
    {
        lock (CACHE_LOCK)
        {
            if (CACHE.TryGetValue(method, out var cached))
                return cached;

            var built = BuildInvoker(method);
            CACHE[method] = built;
            return built;
        }
    }

    private static InteropInvocation BuildInvoker
    (
        MethodInfo method
    )
    {
        var declaringType = method.DeclaringType ?? throw new McpException($"{method.Name} 没有声明类型。");

        var parameters = method.GetParameters();
        var dynamicMethod = new DynamicMethod
        (
            $"dalamud_mcp_{declaringType.Name}_{method.Name}",
            typeof(object),
            [typeof(nint), typeof(object[])],
            typeof(InteropInvoker).Module,
            true
        );

        var il = dynamicMethod.GetILGenerator();

        if (!method.IsStatic)
        {
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, AS_REF_DEFINITION.MakeGenericMethod(declaringType));
        }

        for (var index = 0; index < parameters.Length; index++)
        {
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Ldc_I4, index);
            il.Emit(OpCodes.Ldelem_Ref);
            EmitLoadArgument(il, parameters[index].ParameterType);
        }

        il.Emit(method.IsVirtual ? OpCodes.Callvirt : OpCodes.Call, method);
        EmitReturn(il, method.ReturnType);

        return dynamicMethod.CreateDelegate<InteropInvocation>();
    }

    private static void EmitLoadArgument
    (
        ILGenerator il,
        Type        type
    )
    {
        if (type.IsPointer)
        {
            il.Emit(OpCodes.Unbox_Any, typeof(IntPtr));
            il.Emit(OpCodes.Conv_U);
            return;
        }

        if (type.IsValueType)
        {
            il.Emit(OpCodes.Unbox_Any, type);
            return;
        }

        il.Emit(OpCodes.Castclass, type);
    }

    private static void EmitReturn
    (
        ILGenerator il,
        Type        returnType
    )
    {
        if (returnType == typeof(void))
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ret);
            return;
        }

        if (returnType.IsPointer)
        {
            il.Emit(OpCodes.Conv_U);
            il.Emit(OpCodes.Box, typeof(IntPtr));
            il.Emit(OpCodes.Ret);
            return;
        }

        if (returnType.IsValueType)
            il.Emit(OpCodes.Box, returnType);

        il.Emit(OpCodes.Ret);
    }
}
