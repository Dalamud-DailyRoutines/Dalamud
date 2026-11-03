using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
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
        MethodInfo    method,
        nint          thisPointer,
        JsonElement[] rawArguments
    )
    {
        var parameters = method.GetParameters();

        if (parameters.Length < rawArguments.Length || parameters.Count(parameter => !parameter.IsOptional) > rawArguments.Length)
        {
            throw new McpException
            (
                $"{method.DeclaringType?.Name}.{method.Name} 需要 {parameters.Length} 个参数，实际给出 {rawArguments.Length} 个。"
            );
        }

        var allocations = new List<nint>();

        try
        {
            var converted = new object?[parameters.Length];

            for (var index = 0; index < parameters.Length; index++)
            {
                converted[index] = index < rawArguments.Length ?
                                       ConvertArgument(rawArguments[index], parameters[index].ParameterType, allocations) :
                                       parameters[index].DefaultValue;
            }

            return GetInvoker(method)(thisPointer, converted);
        }
        finally
        {
            foreach (var allocation in allocations)
                Marshal.FreeHGlobal(allocation);
        }
    }

    private static object? ConvertArgument(JsonElement value, Type targetType, List<nint> allocations)
    {
        if (!targetType.IsPointer && targetType != typeof(CStringPointer))
            return RuntimeArguments.Bind(value, targetType);

        switch (value.ValueKind)
        {
            case JsonValueKind.Null:
                return targetType == typeof(CStringPointer) ?
                           (CStringPointer)(byte*)0 :
                           IntPtr.Zero;
        }

        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("text", out var text))
        {
            if (targetType == typeof(CStringPointer))
                return (CStringPointer)AllocUtf8Bytes(text.GetString()!, allocations);

            if (targetType.GetElementType() == typeof(Utf8String))
                return (IntPtr)AllocUtf8String(text.GetString()!, allocations);

            if (targetType.GetElementType() == typeof(byte))
                return (IntPtr)AllocUtf8Bytes(text.GetString()!, allocations);

            throw new McpException($"{targetType} 不支持文本参数。");
        }

        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("address", out var address))
            throw new McpException("原生指针参数需要 {\"address\":\"0x...\"}、{\"text\":\"文本\"} 或 null。");

        var pointer = (nint)MemoryAccess.ParseAddress(address.GetString()!);
        return targetType == typeof(CStringPointer) ?
                   (CStringPointer)(byte*)pointer :
                   pointer;
    }

    private static byte* AllocUtf8Bytes
    (
        string     text,
        List<nint> allocations
    )
    {
        var bytes  = Encoding.UTF8.GetBytes(text);
        var memory = (byte*)Marshal.AllocHGlobal(bytes.Length + 1);
        allocations.Add((nint)memory);

        for (var index = 0; index < bytes.Length; index++)
            memory[index] = bytes[index];

        memory[bytes.Length] = 0;
        return memory;
    }

    private static Utf8String* AllocUtf8String
    (
        string     text,
        List<nint> allocations
    )
    {
        var size   = StructureLayout.GetSize(typeof(Utf8String));
        var bytes  = Encoding.UTF8.GetBytes(text);
        var memory = (byte*)Marshal.AllocHGlobal(size);
        allocations.Add((nint)memory);

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
        *(memory + isEmpty.Offset) = bytes.Length == 0 ?
                                         (byte)1 :
                                         (byte)0;
        *(memory + useInline.Offset) = 1;

        return (Utf8String*)memory;
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

        il.Emit
        (
            method.IsVirtual ?
                OpCodes.Callvirt :
                OpCodes.Call,
            method
        );
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
