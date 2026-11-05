using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Threading;
using Dalamud.Hooking;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>为原生方法合成精确委托；detour 直接持有原函数，卸载后仍可完成在途调用。</summary>
internal sealed class HookBridge
{
    private static readonly ModuleBuilder Module = AssemblyBuilder.DefineDynamicAssembly
        (new AssemblyName("Dalamud.MCP.HookDelegates"), AssemblyBuilderAccess.Run).DefineDynamicModule("Delegates");
    private static readonly Lock             DelegateGate = new();
    private static          int              nextDelegateId;
    private readonly        ObservationStore store;
    private readonly        Observation      observation;
    private                 Delegate         original = null!;
    private                 IDisposable      hook     = null!;

    private HookBridge(ObservationStore store, Observation observation)
    {
        this.store       = store;
        this.observation = observation;
    }

    public static object Install(ObservationStore store, Observation observation, nint address, Type[] parameterTypes, Type returnType)
    {
        if (address == 0 || !MemoryAccess.IsRangeReadable(address, 1))
            throw new McpException("挂钩地址不可读。");

        var bridge       = new HookBridge(store, observation);
        var delegateType = CreateDelegateType(parameterTypes, returnType);
        var detour       = bridge.BuildDetour(delegateType, returnType, parameterTypes);
        var fromAddress =
            typeof(Hook<>).MakeGenericType(delegateType).GetMethod("FromAddress", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic) ??
            throw new McpException("找不到 Hook<T>.FromAddress。");
        var hook = fromAddress.Invoke(null, [address, detour, Assembly.GetExecutingAssembly()]) ?? throw new McpException("创建挂钩失败。");
        bridge.hook = (IDisposable)hook;

        try
        {
            bridge.original     = (Delegate)(hook.GetType().GetProperty("Original")?.GetValue(hook) ?? throw new McpException("找不到原函数。"));
            observation.Handler = detour;
            observation.Address = address;
            hook.GetType().GetMethod("Enable")!.Invoke(hook, null);
            return bridge;
        }
        catch
        {
            bridge.hook.Dispose();
            throw;
        }
    }

    public static void Uninstall(string observationId, object? hook)
    {
        if (hook is HookBridge bridge)
            bridge.hook.Dispose();
    }

    private void Record(object?[] arguments, object? returned)
    {
        try
        {
            this.store.Record
            (
                this.observation.Id,
                "hook",
                "原生方法返回",
                null,
                null,
                new
                {
                    arguments = Array.ConvertAll(arguments, argument => ValueFormatter.Snapshot(argument)),
                    returned  = ValueFormatter.Snapshot(returned),
                    threadId  = Environment.CurrentManagedThreadId
                }
            );
        }
        catch (Exception)
        {
            // ignored
        }
    }

    private Delegate BuildDetour(Type delegateType, Type returnType, Type[] parameterTypes)
    {
        var signature = new Type[parameterTypes.Length + 1];
        signature[0] = typeof(HookBridge);
        parameterTypes.CopyTo(signature, 1);
        var method = new DynamicMethod($"mcp_detour_{this.observation.Id}", returnType, signature, typeof(HookBridge), true);
        var il     = method.GetILGenerator();
        var result = returnType == typeof(void) ?
                         null :
                         il.DeclareLocal(returnType);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldfld,     typeof(HookBridge).GetField(nameof(this.original), BindingFlags.Instance | BindingFlags.NonPublic)!);
        il.Emit(OpCodes.Castclass, delegateType);
        for (var index = 0; index < parameterTypes.Length; index++)
            il.Emit(OpCodes.Ldarg, index + 1);

        il.Emit(OpCodes.Callvirt, delegateType.GetMethod("Invoke")!);
        if (result is not null)
            il.Emit(OpCodes.Stloc, result);

        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldc_I4, parameterTypes.Length);
        il.Emit(OpCodes.Newarr, typeof(object));

        for (var index = 0; index < parameterTypes.Length; index++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, index);
            il.Emit(OpCodes.Ldarg,  index + 1);
            EmitBox(il, parameterTypes[index]);
            il.Emit(OpCodes.Stelem_Ref);
        }

        if (result is null)
            il.Emit(OpCodes.Ldnull);
        else
        {
            il.Emit(OpCodes.Ldloc, result);
            EmitBox(il, returnType);
        }

        il.Emit(OpCodes.Call, typeof(HookBridge).GetMethod(nameof(Record), BindingFlags.Instance | BindingFlags.NonPublic)!);
        if (result is not null)
            il.Emit(OpCodes.Ldloc, result);

        il.Emit(OpCodes.Ret);
        return method.CreateDelegate(delegateType, this);
    }

    private static void EmitBox(ILGenerator il, Type type)
    {
        if (type.IsPointer)
        {
            il.Emit(OpCodes.Conv_I);
            il.Emit(OpCodes.Box, typeof(nint));
        }
        else if (type.IsValueType)
        {
            il.Emit(OpCodes.Box, type);
        }
    }

    private static Type CreateDelegateType(Type[] parameters, Type returnType)
    {
        lock (DelegateGate)
        {
            var type = Module.DefineType($"HookDelegate{++nextDelegateId}", TypeAttributes.Public | TypeAttributes.Sealed, typeof(MulticastDelegate));
            var constructor = type.DefineConstructor
                (MethodAttributes.Public | MethodAttributes.RTSpecialName | MethodAttributes.HideBySig, CallingConventions.Standard, [typeof(object), typeof(nint)]);
            constructor.SetImplementationFlags(MethodImplAttributes.Runtime);
            var invoke = type.DefineMethod
                ("Invoke", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig | MethodAttributes.NewSlot, returnType, parameters);
            var marshalConstructor = typeof(MarshalAsAttribute).GetConstructor([typeof(UnmanagedType)])!;
            if (returnType == typeof(bool))
                invoke.DefineParameter(0, ParameterAttributes.Retval, null).SetCustomAttribute(new CustomAttributeBuilder(marshalConstructor, [UnmanagedType.I1]));

            for (var index = 0; index < parameters.Length; index++)
            {
                if (parameters[index] == typeof(bool))
                    invoke.DefineParameter(index + 1, ParameterAttributes.None, null).SetCustomAttribute
                        (new CustomAttributeBuilder(marshalConstructor, [UnmanagedType.I1]));
            }

            invoke.SetImplementationFlags(MethodImplAttributes.Runtime);
            return type.CreateType()!;
        }
    }
}
