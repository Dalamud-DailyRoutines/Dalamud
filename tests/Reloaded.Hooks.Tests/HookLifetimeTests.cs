using System.Diagnostics;
using System.Runtime.InteropServices;
using Iced.Intel;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Hooks.Tools;
using Reloaded.Memory.Buffers;
using Xunit;
using static Iced.Intel.AssemblerRegisters;
using Wrapper = Reloaded.Hooks.X64.Wrapper;

namespace Reloaded.Hooks.Tests;

public sealed class HookLifetimeTests
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BinaryFunction(int left, int right);

    [Function(new[] { FunctionAttribute.Register.rdi, FunctionAttribute.Register.rsi }, FunctionAttribute.Register.rax, false)]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int CustomFunction(int left, int right);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public unsafe void JumpContainsAlignedTargetWithoutDistanceConstraint(bool is64Bit)
    {
        var target = is64Bit ? nuint.CreateChecked(FAR_ADDRESS) : (nuint)0x12345678;
        var address = Utilities.CreateJump(target, is64Bit, 64);
        var bytes = new ReadOnlySpan<byte>((void*)address, 64);
        Assert.Equal((nuint)0, address % 16);
        Assert.Equal(0xFF, bytes[0]);
        Assert.Equal(0x25, bytes[1]);
        Assert.Equal(0xCC, bytes[6]);
        Assert.Equal(0xCC, bytes[7]);

        if (is64Bit)
        {
            Assert.Equal(2, *(int*)(address + 2));
            Assert.Equal(target, *(nuint*)(address + 8));
        }
        else
        {
            Assert.Equal((uint)(address + 8), *(uint*)(address + 2));
            Assert.Equal((uint)target, *(uint*)(address + 8));
        }

        Assert.All(bytes[16..].ToArray(), value => Assert.Equal(0xCC, value));
    }

    [Fact]
    public void FarJumpExecutesWithoutChangingArguments()
    {
        Utilities.WritePointer(0);
        using var native = new NativeFunction([0x8D, 0x04, 0x11, 0xC3]);
        var jump = Utilities.CreateJump(native.Address, true);
        var distance = native.Address > jump ? native.Address - jump : jump - native.Address;
        Assert.True(distance > int.MaxValue);
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)jump);
        Assert.Equal(42, function(17, 25));
    }

    [Fact]
    public unsafe void RepeatedActivationAndSwitchingPreserveCode()
    {
        using var native = CreateAddition();
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)native.Address);
        var hook = new Hook<BinaryFunction>((left, right) => left * right, native.Address);
        var stub = hook.ReverseWrapper.WrapperPointer;
        var code = new ReadOnlySpan<byte>((void*)stub, 8).ToArray();
        hook.Enable();
        hook.Disable();
        Assert.False(hook.IsHookActivated);
        Assert.Equal(7, function(3, 4));

        try
        {
            hook.Activate();
            hook.Activate();
            Assert.Equal(12, function(3, 4));
            Assert.Equal(7, hook.OriginalFunction(3, 4));
            hook.Disable();
            hook.Activate();
            Assert.False(hook.IsHookEnabled);
            Assert.Equal(7, function(3, 4));
            hook.Enable();
            Assert.Equal(12, function(3, 4));
            Assert.Equal(code, new ReadOnlySpan<byte>((void*)stub, 8).ToArray());
        }
        finally
        {
            hook.Disable();
            GC.KeepAlive(hook);
        }
    }

    [Fact]
    public unsafe void NativeDetourCanBeEnabledAndDisabled()
    {
        using var native = CreateAddition();
        using var detour = new NativeFunction([0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)native.Address);
        var hook = new Hook<BinaryFunction>((void*)detour.Address, native.Address);

        try
        {
            hook.Activate();
            Assert.Equal(42, function(3, 4));
            Assert.Equal(7, hook.OriginalFunction(3, 4));
            hook.Disable();
            Assert.Equal(7, function(3, 4));
            hook.Enable();
            Assert.Equal(42, function(3, 4));
        }
        finally
        {
            hook.Disable();
        }
    }

    [Fact]
    public void StackedHooksCanBeDisabledInEitherOrder()
    {
        using var native = CreateAddition();
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)native.Address);
        Hook<BinaryFunction> lower = null!;
        Hook<BinaryFunction> upper = null!;
        lower = new Hook<BinaryFunction>((left, right) => lower.OriginalFunction(left, right) + 10, native.Address);
        lower.Activate();

        try
        {
            upper = new Hook<BinaryFunction>((left, right) => upper.OriginalFunction(left, right) * 2, native.Address);
            upper.Activate();
            Assert.Equal(34, function(3, 4));
            lower.Disable();
            Assert.Equal(14, function(3, 4));
            upper.Disable();
            Assert.Equal(7, function(3, 4));
            lower.Enable();
            Assert.Equal(17, function(3, 4));
            upper.Enable();
            Assert.Equal(34, function(3, 4));
        }
        finally
        {
            upper?.Disable();
            lower.Disable();
            GC.KeepAlive(upper);
            GC.KeepAlive(lower);
        }
    }

    [Fact]
    public void ReloadsReuseBuffersAndLeaveDisabledChainsCallable()
    {
        using var native = CreateAddition();
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)native.Address);
        var buffers = new HashSet<nuint>();

        for (var index = 0; index < 256; index++)
        {
            var hook = new Hook<BinaryFunction>((left, right) => left * right, native.Address);
            buffers.Add((nuint)hook.ReverseWrapper.WrapperPointer / BUFFER_GRANULARITY);

            try
            {
                hook.Activate();
                Assert.Equal(12, function(3, 4));
                Assert.Equal(7, hook.OriginalFunction(3, 4));
            }
            finally
            {
                hook.Disable();
                GC.KeepAlive(hook);
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        Assert.Equal(7, function(3, 4));
        Assert.InRange(buffers.Count, 1, 2);
    }

    [Fact]
    public async Task SwitchingWhileCallingOnlyObservesCompleteTargets()
    {
        using var native = CreateAddition();
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)native.Address);
        var hook = new Hook<BinaryFunction>((left, right) => left * right, native.Address);
        hook.Activate();
        var cancellationToken = TestContext.Current.CancellationToken;

        try
        {
            await Task.WhenAll(Task.Run(() =>
            {
                for (var index = 0; index < 20000; index++)
                {
                    var result = function(3, 4);
                    Assert.True(result is 7 or 12);
                }
            }, cancellationToken), Task.Run(() =>
            {
                for (var index = 0; index < 10000; index++)
                {
                    hook.Disable();
                    hook.Enable();
                }
            }, cancellationToken));
        }
        finally
        {
            hook.Disable();
            GC.KeepAlive(hook);
        }
    }

    [Fact]
    public void CustomConventionHookUsesIndependentSwitchingStub()
    {
        using var native = new NativeFunction([0x8D, 0x04, 0x37, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3]);
        var function = Wrapper.Create<CustomFunction>(native.Address);
        Hook<CustomFunction> hook = null!;
        hook = new Hook<CustomFunction>((left, right) => hook.OriginalFunction(left, right) * 2, native.Address);

        try
        {
            hook.Activate();
            Assert.Equal(14, function(3, 4));
            Assert.Equal(7, hook.OriginalFunction(3, 4));
            hook.Disable();
            Assert.Equal(7, function(3, 4));
            hook.Enable();
            Assert.Equal(14, function(3, 4));
        }
        finally
        {
            hook.Disable();
            GC.KeepAlive(hook);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FarConventionCallPreservesStackAlignment(bool preserveRegister)
    {
        Utilities.WritePointer(0);
        var assembler = new Assembler(64);
        assembler.mov(rax, rsp);
        assembler.and(rax, 15);
        assembler.ret();
        using var stream = new MemoryStream();
        assembler.Assemble(new StreamCodeWriter(stream), 0);
        using var native = new NativeFunction(stream.ToArray());
        var convention = new FunctionAttribute(
            [FunctionAttribute.Register.rcx, FunctionAttribute.Register.rdx],
            FunctionAttribute.Register.rax,
            true,
            preserveRegister ? [FunctionAttribute.Register.rbx] : []);
        var wrapper = Wrapper.Create<BinaryFunction>(native.Address, FunctionAttribute.Microsoft, convention);
        var distance = native.Address > wrapper ? native.Address - wrapper : wrapper - native.Address;
        Assert.True(distance > int.MaxValue);
        var function = Marshal.GetDelegateForFunctionPointer<BinaryFunction>((nint)wrapper);
        Assert.Equal(8, function(0, 0));
    }

    private static NativeFunction CreateAddition() => new([0x8D, 0x04, 0x11, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3]);

    private sealed class NativeFunction : IDisposable
    {
        private readonly MemoryBufferHelper allocator = new(Process.GetCurrentProcess());

        public NativeFunction(byte[] code)
        {
            Address = allocator.Allocate(code.Length, nuint.CreateChecked(0x100000000UL), nuint.CreateChecked(MAXIMUM_ADDRESS)).MemoryAddress;
            Marshal.Copy(code, 0, (nint)Address, code.Length);
        }

        public nuint Address { get; }

        public void Dispose() => allocator.Free(Address);
    }

    #region 常量

    private const ulong FAR_ADDRESS = 0x20000000000;
    private const ulong MAXIMUM_ADDRESS = 0x7FFFFFFEFFFF;
    private const uint BUFFER_GRANULARITY = 65536;

    #endregion
}
