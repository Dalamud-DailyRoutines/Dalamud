using System.Runtime.InteropServices;

namespace Dalamud;

/// <summary>
/// 调试所需的原生入口：线程控制、向量化异常处理、输入注入与窗口查询。
/// </summary>
internal static unsafe partial class NativeApi
{
    internal const uint THREAD_SUSPEND_RESUME    = 0x0002;
    internal const uint THREAD_GET_CONTEXT       = 0x0008;
    internal const uint THREAD_SET_CONTEXT       = 0x0010;
    internal const uint THREAD_QUERY_INFORMATION = 0x0040;

    internal const uint CONTEXT_AMD64          = 0x00100000;
    internal const uint CONTEXT_CONTROL        = CONTEXT_AMD64   | 0x1;
    internal const uint CONTEXT_INTEGER        = CONTEXT_AMD64   | 0x2;
    internal const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64   | 0x8;
    internal const uint CONTEXT_FULL           = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

    internal const uint INPUT_MOUSE             = 0;
    internal const uint INPUT_KEYBOARD          = 1;
    internal const uint KEYEVENTF_KEYUP         = 0x0002;
    internal const uint KEYEVENTF_UNICODE       = 0x0004;
    internal const uint MOUSEEVENTF_MOVE        = 0x0001;
    internal const uint MOUSEEVENTF_LEFTDOWN    = 0x0002;
    internal const uint MOUSEEVENTF_LEFTUP      = 0x0004;
    internal const uint MOUSEEVENTF_RIGHTDOWN   = 0x0008;
    internal const uint MOUSEEVENTF_RIGHTUP     = 0x0010;
    internal const uint MOUSEEVENTF_MIDDLEDOWN  = 0x0020;
    internal const uint MOUSEEVENTF_MIDDLEUP    = 0x0040;
    internal const uint MOUSEEVENTF_WHEEL       = 0x0800;
    internal const uint MOUSEEVENTF_ABSOLUTE    = 0x8000;
    internal const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;

    internal const int SM_CXSCREEN = 0;
    internal const int SM_CYSCREEN = 1;
    internal const int SW_RESTORE  = 9;

    internal const int SM_XVIRTUALSCREEN  = 76;
    internal const int SM_YVIRTUALSCREEN  = 77;
    internal const int SM_CXVIRTUALSCREEN = 78;
    internal const int SM_CYVIRTUALSCREEN = 79;

    internal const uint MAPVK_VK_TO_VSC = 0;

    internal const uint WM_KEYDOWN     = 0x0100;
    internal const uint WM_KEYUP       = 0x0101;
    internal const uint WM_CHAR        = 0x0102;
    internal const uint WM_MOUSEMOVE   = 0x0200;
    internal const uint WM_LBUTTONDOWN = 0x0201;
    internal const uint WM_LBUTTONUP   = 0x0202;
    internal const uint WM_RBUTTONDOWN = 0x0204;
    internal const uint WM_RBUTTONUP   = 0x0205;
    internal const uint WM_MBUTTONDOWN = 0x0207;
    internal const uint WM_MBUTTONUP   = 0x0208;
    internal const uint WM_MOUSEWHEEL  = 0x020A;

    internal const int MK_LBUTTON = 0x0001;
    internal const int MK_RBUTTON = 0x0002;
    internal const int MK_MBUTTON = 0x0010;

    internal const uint MEM_COMMIT             = 0x1000;
    internal const uint PAGE_NOACCESS          = 0x01;
    internal const uint PAGE_READONLY          = 0x02;
    internal const uint PAGE_READWRITE         = 0x04;
    internal const uint PAGE_WRITECOPY         = 0x08;
    internal const uint PAGE_EXECUTE_READ      = 0x20;
    internal const uint PAGE_EXECUTE_READWRITE = 0x40;
    internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    internal const uint PAGE_GUARD             = 0x100;

    /// <summary>
    /// x64 的 CONTEXT，只声明调试与单步需要的部分。
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 0x4D0)]
    internal struct Context64
    {
        /// <summary>ContextFlags。</summary>
        [FieldOffset(0x30)]
        public uint ContextFlags;

        /// <summary>EFlags，单步位在此。</summary>
        [FieldOffset(0x44)]
        public uint EFlags;

        /// <summary>调试寄存器 0。</summary>
        [FieldOffset(0x48)]
        public ulong Dr0;

        /// <summary>调试寄存器 1。</summary>
        [FieldOffset(0x50)]
        public ulong Dr1;

        /// <summary>调试寄存器 2。</summary>
        [FieldOffset(0x58)]
        public ulong Dr2;

        /// <summary>调试寄存器 3。</summary>
        [FieldOffset(0x60)]
        public ulong Dr3;

        /// <summary>调试寄存器 6。</summary>
        [FieldOffset(0x68)]
        public ulong Dr6;

        /// <summary>调试寄存器 7。</summary>
        [FieldOffset(0x70)]
        public ulong Dr7;

        /// <summary>Rax。</summary>
        [FieldOffset(0x78)]
        public ulong Rax;

        /// <summary>Rcx。</summary>
        [FieldOffset(0x80)]
        public ulong Rcx;

        /// <summary>Rdx。</summary>
        [FieldOffset(0x88)]
        public ulong Rdx;

        /// <summary>Rbx。</summary>
        [FieldOffset(0x90)]
        public ulong Rbx;

        /// <summary>Rsp。</summary>
        [FieldOffset(0x98)]
        public ulong Rsp;

        /// <summary>Rbp。</summary>
        [FieldOffset(0xA0)]
        public ulong Rbp;

        /// <summary>Rsi。</summary>
        [FieldOffset(0xA8)]
        public ulong Rsi;

        /// <summary>Rdi。</summary>
        [FieldOffset(0xB0)]
        public ulong Rdi;

        /// <summary>R8。</summary>
        [FieldOffset(0xB8)]
        public ulong R8;

        /// <summary>R9。</summary>
        [FieldOffset(0xC0)]
        public ulong R9;

        /// <summary>R10。</summary>
        [FieldOffset(0xC8)]
        public ulong R10;

        /// <summary>R11。</summary>
        [FieldOffset(0xD0)]
        public ulong R11;

        /// <summary>R12。</summary>
        [FieldOffset(0xD8)]
        public ulong R12;

        /// <summary>R13。</summary>
        [FieldOffset(0xE0)]
        public ulong R13;

        /// <summary>R14。</summary>
        [FieldOffset(0xE8)]
        public ulong R14;

        /// <summary>R15。</summary>
        [FieldOffset(0xF0)]
        public ulong R15;

        /// <summary>Rip。</summary>
        [FieldOffset(0xF8)]
        public ulong Rip;
    }

    /// <summary>矩形。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Rect
    {
        /// <summary>左。</summary>
        public int Left;

        /// <summary>上。</summary>
        public int Top;

        /// <summary>右。</summary>
        public int Right;

        /// <summary>下。</summary>
        public int Bottom;
    }

    /// <summary>点。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Point
    {
        /// <summary>X。</summary>
        public int X;

        /// <summary>Y。</summary>
        public int Y;
    }

    /// <summary>键盘输入。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyboardInput
    {
        /// <summary>虚拟键码。</summary>
        public ushort VirtualKey;

        /// <summary>扫描码。</summary>
        public ushort ScanCode;

        /// <summary>标志。</summary>
        public uint Flags;

        /// <summary>时间戳。</summary>
        public uint Time;

        /// <summary>附加信息。</summary>
        public nint ExtraInfo;
    }

    /// <summary>鼠标输入。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct MouseInput
    {
        /// <summary>X。</summary>
        public int Dx;

        /// <summary>Y。</summary>
        public int Dy;

        /// <summary>滚轮数据。</summary>
        public uint MouseData;

        /// <summary>标志。</summary>
        public uint Flags;

        /// <summary>时间戳。</summary>
        public uint Time;

        /// <summary>附加信息。</summary>
        public nint ExtraInfo;
    }

    /// <summary>输入联合体。</summary>
    [StructLayout(LayoutKind.Explicit)]
    internal struct InputUnion
    {
        /// <summary>键盘。</summary>
        [FieldOffset(0)]
        public KeyboardInput Keyboard;

        /// <summary>鼠标。</summary>
        [FieldOffset(0)]
        public MouseInput Mouse;
    }

    /// <summary>一条输入事件。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct Input
    {
        /// <summary>类型。</summary>
        public uint Type;

        /// <summary>内容。</summary>
        public InputUnion Union;
    }

    /// <summary>VirtualQuery 的返回结构。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryBasicInformation
    {
        /// <summary>区域起始地址。</summary>
        public nint BaseAddress;

        /// <summary>分配基址。</summary>
        public nint AllocationBase;

        /// <summary>分配保护。</summary>
        public uint AllocationProtect;

        /// <summary>分区 ID。</summary>
        public ushort PartitionId;

        /// <summary>区域大小。</summary>
        public nuint RegionSize;

        /// <summary>提交状态。</summary>
        public uint State;

        /// <summary>当前保护。</summary>
        public uint Protect;

        /// <summary>类型。</summary>
        public uint Type;
    }

    [LibraryImport("kernel32.dll")]
    internal static partial uint GetCurrentThreadId();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint OpenThread
    (
        uint                                 desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint                                 threadId
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int SuspendThread
    (
        nint thread
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int ResumeThread
    (
        nint thread
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetThreadContext
    (
        nint          thread,
        ref Context64 context
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetThreadContext
    (
        nint          thread,
        ref Context64 context
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle
    (
        nint handle
    );

    [LibraryImport("user32.dll", SetLastError = true)]
    internal static partial uint SendInput
    (
        uint   count,
        Input* inputs,
        int    size
    );

    [LibraryImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool PostMessage
    (
        nint  window,
        uint  message,
        nint  wParam,
        nint  lParam
    );

    [LibraryImport("user32.dll")]
    internal static partial nint GetForegroundWindow();

    [LibraryImport("user32.dll")]
    internal static partial uint GetWindowThreadProcessId
    (
        nint     window,
        out uint processId
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetClientRect
    (
        nint     window,
        out Rect rect
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetWindowRect
    (
        nint     window,
        out Rect rect
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetForegroundWindow
    (
        nint window
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsIconic
    (
        nint window
    );

    [LibraryImport("user32.dll")]
    internal static partial int GetSystemMetrics
    (
        int index
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ScreenToClient
    (
        nint      window,
        ref Point point
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ClientToScreen
    (
        nint      window,
        ref Point point
    );

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetCursorPos
    (
        out Point point
    );

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetCursorPos
    (
        int x,
        int y
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ShowWindow
    (
        nint window,
        int  command
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool BringWindowToTop
    (
        nint window
    );

    [LibraryImport("user32.dll")]
    internal static partial nint SetFocus
    (
        nint window
    );

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AttachThreadInput
    (
        uint                                 attach,
        uint                                 attachTo,
        [MarshalAs(UnmanagedType.Bool)] bool attachInput
    );

    [LibraryImport("user32.dll")]
    internal static partial uint MapVirtualKey
    (
        uint code,
        uint mapType
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nuint VirtualQuery
    (
        nint                       address,
        out MemoryBasicInformation buffer,
        nuint                      length
    );
}
