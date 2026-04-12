#include "pch.h"

#include "xivfixes.h"

#include "DalamudStartInfo.h"
#include "hooks.h"
#include "logging.h"
#include "ntdll.h"
#include "utils.h"

void xivfixes::unhook_dll(bool bApply) {
    static const auto LogTag = "[xivfixes:unhook_dll]";
    static const auto LogTagW = L"[xivfixes:unhook_dll]";

    if (!bApply)
        return;

    const auto mods = utils::loaded_module::all_modules();

    for (size_t i = 0; i < mods.size(); i++) {
        const auto& mod = mods[i];
        const auto path = mod.path();
        if (!path) {
            logging::W(
                "{} [{}/{}] 模块 0x{:X}: 解析路径失败: {}",
                LogTag,
                i + 1,
                mods.size(),
                mod.address_int(),
                path.error().describe());
            return;
        }

        const auto version = mod.get_file_version()
            .transform([](const auto& v) { return utils::format_file_version(v.get()); })
            .value_or(L"<未知>");

        const auto description = mod.get_description()
            .value_or(L"<未知>");

        logging::I(
            R"({} [{}/{}] 模块 0x{:X} ~ 0x{:X} (0x{:X}): "{}" ("{}" 版本 {}))",
            LogTagW,
            i + 1,
            mods.size(),
            mod.address_int(),
            mod.address_int() + mod.image_size(),
            mod.image_size(),
            path->wstring(),
            description,
            version);

        const auto moduleName = unicode::convert<std::string>(path->filename().wstring());

        const auto& sectionHeader = mod.section_header(".text");
        const auto section = mod.span_as<char>(sectionHeader.VirtualAddress, sectionHeader.Misc.VirtualSize);
        if (section.empty()) {
            logging::W("{} 错误: .text[VA:VA + VS] 为空", LogTag);
            return;
        }

        auto hFsDllRaw = CreateFileW(path->c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFsDllRaw == INVALID_HANDLE_VALUE) {
            logging::W("{} 模块已加载到当前进程, 但无法打开文件: Win32 错误 {}", LogTag, GetLastError());
            return;
        }

        auto hFsDll = std::unique_ptr<void, decltype(&CloseHandle)>(hFsDllRaw, &CloseHandle);
        std::vector<char> buf(section.size());
        SetFilePointer(hFsDll.get(), sectionHeader.PointerToRawData, nullptr, FILE_CURRENT);
        if (DWORD read{}; ReadFile(hFsDll.get(), &buf[0], static_cast<DWORD>(buf.size()), &read, nullptr)) {
            if (read < section.size_bytes()) {
                logging::W("{} ReadFile: 已读取 {} 字节, 少于请求的 {} 字节", LogTagW, read, section.size_bytes());
                return;
            }
        } else {
            logging::I("{} ReadFile: Win32 错误 {}", LogTagW, GetLastError());
            return;
        }

        const auto doRestore = g_startInfo.BootUnhookDlls.contains(unicode::convert<std::string>(path->filename().u8string()));
        try {
            std::optional<utils::memory_tenderizer> tenderizer;
            std::string formatBuf;
            for (size_t inst = 0, instructionLength = 1, printed = 0; inst < buf.size(); inst += instructionLength) {
                if (section[inst] == buf[inst]) {
                    instructionLength = 1;
                    continue;
                }

                const auto rva = sectionHeader.VirtualAddress + inst;
                nmd_x86_instruction instruction{};
                if (!nmd_x86_decode(&section[inst], section.size() - inst, &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_ALL)) {
                    instructionLength = 1;
                    if (printed < 64) {
                        logging::W("{} {}+0x{:0X}: dd {:02X}", LogTag, moduleName, rva, static_cast<uint8_t>(section[inst]));
                        printed++;
                    }
                } else {
                    instructionLength = instruction.length;
                    if (printed < 64) {
                        formatBuf.resize(128);
                        nmd_x86_format(&instruction, &formatBuf[0], reinterpret_cast<size_t>(&section[inst]), NMD_X86_FORMAT_FLAGS_DEFAULT | NMD_X86_FORMAT_FLAGS_BYTES);
                        formatBuf.resize(strnlen(&formatBuf[0], formatBuf.size()));

                        const auto& directory = mod.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
                        const auto& exportDirectory = mod.ref_as<IMAGE_EXPORT_DIRECTORY>(directory.VirtualAddress);
                        const auto names = mod.span_as<DWORD>(exportDirectory.AddressOfNames, exportDirectory.NumberOfNames);
                        const auto ordinals = mod.span_as<WORD>(exportDirectory.AddressOfNameOrdinals, exportDirectory.NumberOfNames);
                        const auto functions = mod.span_as<DWORD>(exportDirectory.AddressOfFunctions, exportDirectory.NumberOfFunctions);

                        std::string resolvedExportName;
                        for (size_t nameIndex = 0; nameIndex < names.size(); ++nameIndex) {
                            std::string_view name;
                            if (const char* pcszName = mod.address_as<char>(names[nameIndex]); pcszName < mod.address() || pcszName >= mod.address() + mod.image_size()) {
                                if (IsBadReadPtr(pcszName, 256)) {
                                    logging::W("{} 名称 #{} 指向了可执行映像外的无效地址, 已跳过", LogTag, nameIndex);
                                    continue;
                                }

                                name = std::string_view(pcszName, strnlen(pcszName, 256));
                                logging::W("{} 名称 #{} 指向了可执行映像外看似有效的地址: {}", LogTag, nameIndex, name);
                            }

                            if (ordinals[nameIndex] >= functions.size()) {
                                logging::W("{} 序号 #{} 指向的函数索引 #{} >= #{}, 已跳过", LogTag, nameIndex, ordinals[nameIndex], functions.size());
                                continue;
                            }

                            const auto rva = functions[ordinals[nameIndex]];
                            if (rva == &section[inst] - mod.address()) {
                                resolvedExportName = std::format("[export:{}]", name);
                                break;
                            }
                        }

                        logging::W("{} {}+0x{:0X}{}: {}", LogTag, moduleName, rva, resolvedExportName, formatBuf);
                        printed++;
                    }
                }

                if (doRestore) {
                    if (!tenderizer)
                        tenderizer.emplace(section, PAGE_EXECUTE_READWRITE);
                    memcpy(&section[inst], &buf[inst], instructionLength);
                }
            }

            if (tenderizer)
                logging::I("{} 校验并覆盖完成", LogTag);
            else if (doRestore)
                logging::I("{} 校验完成, 无需覆盖", LogTag);

        } catch (const std::exception& e) {
            logging::W("{} 错误: {}", LogTag, e.what());
        }
    }
}

using TFnGetInputDeviceManager = void* ();
static TFnGetInputDeviceManager* GetGetInputDeviceManager(HWND hwnd) {
    static TFnGetInputDeviceManager* pCached = nullptr;
    if (pCached)
        return pCached;

    return pCached = utils::signature_finder()
        .look_in(utils::loaded_module(g_hGameInstance), ".text")
        .look_for_hex("e8 ?? ?? ?? ?? 48 8b 58 10 48 85 db")
        .find_one()
        .resolve_jump_target<TFnGetInputDeviceManager*>();
}

void xivfixes::prevent_devicechange_crashes(bool bApply) {
    static const char* LogTag = "[xivfixes:prevent_devicechange_crashes]";

    // We hook RegisterClassExA, since if the game has already launched (inject mode), the very crash we're trying to fix cannot happen at that point.
    static std::optional<hooks::import_hook<decltype(RegisterClassExA)>> s_hookRegisterClassExA;
    static WNDPROC s_pfnGameWndProc = nullptr;

    // We're intentionally leaking memory for this one.
    static const auto s_pfnBinder = static_cast<WNDPROC>(VirtualAlloc(nullptr, 64, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    static const auto s_pfnAlternativeWndProc = static_cast<WNDPROC>([](HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        if (uMsg == WM_DEVICECHANGE && wParam == DBT_DEVNODES_CHANGED) {
            try {
                if (!GetGetInputDeviceManager(hWnd)()) {
                    logging::I("{} WndProc(0x{:X}, WM_DEVICECHANGE, DBT_DEVNODES_CHANGED, {}) 已调用, 但游戏尚未初始化 InputDeviceManager, 不执行任何操作", LogTag, reinterpret_cast<size_t>(hWnd), lParam);
                    return 0;
                }
            } catch (const std::exception& e) {
                logging::W("{} WndProc(0x{:X}, WM_DEVICECHANGE, DBT_DEVNODES_CHANGED, {}) 已调用, 但解析 GetInputDeviceManager 地址失败: {}", LogTag, reinterpret_cast<size_t>(hWnd), lParam, e.what());
            }
        }

        // While at it, prevent game from entering restored mode if the game does not have window frames (borderless window/fullscreen.)
        if (uMsg == WM_SIZE && wParam == SIZE_RESTORED
            && (GetWindowLongW(hWnd, GWL_STYLE) & WS_POPUP)  // Is the game not in windowed mode?
            && !((GetKeyState(VK_LWIN) | GetKeyState(VK_RWIN)) & 0x8000)  // Allow Win+Shift+Left/Right key combinations to temporarily restore the window to let it move across displays.
            )
            return ShowWindow(hWnd, SW_MAXIMIZE);

        return s_pfnGameWndProc(hWnd, uMsg, wParam, lParam);
    });

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("prevent_devicechange_crashes")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }

        s_hookRegisterClassExA.emplace("user32.dll!RegisterClassExA (prevent_devicechange_crashes)", "user32.dll", "RegisterClassExA", 0);
        s_hookRegisterClassExA->set_detour([](const WNDCLASSEXA* pWndClassExA)->ATOM {
            // If this RegisterClassExA isn't initiated by the game executable, we do not handle it.
            if (pWndClassExA->hInstance != GetModuleHandleW(nullptr))
                return s_hookRegisterClassExA->call_original(pWndClassExA);

            // If this RegisterClassExA isn't about FFXIVGAME, the game's main window, we do not handle it.
            if (strncmp(pWndClassExA->lpszClassName, "FFXIVGAME", 10) != 0)
                return s_hookRegisterClassExA->call_original(pWndClassExA);

            // push qword ptr [rip+1]
            // ret
            // <pointer to new wndproc>
            memcpy(s_pfnBinder, "\xFF\x35\x01\x00\x00\x00\xC3", 7);
            *reinterpret_cast<void**>(reinterpret_cast<char*>(s_pfnBinder) + 7) = s_pfnAlternativeWndProc;
            
            s_pfnGameWndProc = pWndClassExA->lpfnWndProc;

            WNDCLASSEXA wndClassExA = *pWndClassExA;
            wndClassExA.lpfnWndProc = s_pfnBinder;
            return s_hookRegisterClassExA->call_original(&wndClassExA);
        });

        logging::I("{} 已启用", LogTag);

    } else {
        if (s_hookRegisterClassExA) {
            logging::I("{} 正在禁用 RegisterClassExA 挂钩", LogTag);
            s_hookRegisterClassExA.reset();
        }

        *reinterpret_cast<void**>(reinterpret_cast<char*>(s_pfnBinder) + 7) = s_pfnGameWndProc;
    }
}

static bool is_xivalex(const std::filesystem::path& dllPath) {
    DWORD verHandle = 0;
    std::vector<uint8_t> block;
    block.resize(GetFileVersionInfoSizeW(dllPath.c_str(), &verHandle));
    if (block.empty())
        return false;
    if (!GetFileVersionInfoW(dllPath.c_str(), 0, static_cast<DWORD>(block.size()), &block[0]))
        return false;
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } * lpTranslate;
    UINT cbTranslate;
    if (!VerQueryValueW(&block[0],
        TEXT("\\VarFileInfo\\Translation"),
        reinterpret_cast<LPVOID*>(&lpTranslate),
        &cbTranslate)) {
        return false;
    }

    for (size_t i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++) {
        wchar_t* buf = nullptr;
        UINT size = 0;
        if (!VerQueryValueW(&block[0],
            std::format(L"\\StringFileInfo\\{:04x}{:04x}\\FileDescription",
                lpTranslate[i].wLanguage,
                lpTranslate[i].wCodePage).c_str(),
            reinterpret_cast<LPVOID*>(&buf),
            &size)) {
            continue;
        }
        auto currName = std::wstring_view(buf, size);
        while (!currName.empty() && currName.back() == L'\0')
            currName = currName.substr(0, currName.size() - 1);
        if (currName.empty())
            continue;
        if (currName == L"XivAlexander Main DLL")
            return true;
    }
    return false;
}

static bool is_openprocess_already_dealt_with() {
    static const auto s_value = [] {
        for (const auto& mod : utils::loaded_module::all_modules()) {
            const auto path = mod.path().value_or({});
            if (path.empty())
                continue;
            if (is_xivalex(path))
                return true;
        }
        return false;
    }();
    return s_value;
}

void xivfixes::disable_game_openprocess_access_check(bool bApply) {
    static const char* LogTag = "[xivfixes:disable_game_openprocess_access_check]";
    static std::optional<hooks::import_hook<decltype(OpenProcess)>> s_hook;

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("disable_game_openprocess_access_check")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }
        if (is_openprocess_already_dealt_with()) {
            logging::I("{} 已由其他模块处理", LogTag);
            return;
        }

        s_hook.emplace("kernel32.dll!OpenProcess (import, disable_game_openprocess_access_check)", "kernel32.dll", "OpenProcess", 0);
        s_hook->set_detour([](DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)->HANDLE {
            logging::I("{} 线程 {} 调用了 OpenProcess(0x{:08X}, {}, {})", LogTag, GetCurrentThreadId(), dwDesiredAccess, bInheritHandle, dwProcessId);

            if (dwProcessId == GetCurrentProcessId()) {
                // Prevent game from feeling unsafe that it restarts
                if (dwDesiredAccess & PROCESS_VM_WRITE) {
                    logging::I("{} 正在返回失败, 并将最后错误码设为 ERROR_ACCESS_DENIED(5)", LogTag);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return {};
                }
            }

            return s_hook->call_original(dwDesiredAccess, bInheritHandle, dwProcessId);
        });

        logging::I("{} 已启用", LogTag);
    } else {
        if (s_hook) {
            logging::I("{} 正在禁用 OpenProcess 挂钩", LogTag);
            s_hook.reset();
        }
    }
}

void xivfixes::redirect_openprocess(bool bApply) {
    static const char* LogTag = "[xivfixes:redirect_openprocess]";
    static std::shared_ptr<hooks::base_untyped_hook> s_hook;
    static std::mutex s_silenceSetMtx;
    static std::set<DWORD> s_silenceSet;

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("redirect_openprocess")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }
        if (is_openprocess_already_dealt_with()) {
            logging::I("{} 已由其他模块处理", LogTag);
            return;
        }

        if (g_startInfo.BootDotnetOpenProcessHookMode == DalamudStartInfo::DotNetOpenProcessHookMode::ImportHooks) {
            auto hook = std::make_shared<hooks::global_import_hook<decltype(OpenProcess)>>("kernel32.dll!OpenProcess (global import, redirect_openprocess)", L"kernel32.dll", "OpenProcess");
            hook->set_detour([hook = hook.get()](DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)->HANDLE {
                if (dwProcessId == GetCurrentProcessId()) {
                    if (s_silenceSet.emplace(GetCurrentThreadId()).second)
                        logging::I("{} 线程 {} 调用了 OpenProcess(0x{:08X}, {}, {}), 正在重定向到 DuplicateHandle", LogTag, GetCurrentThreadId(), dwDesiredAccess, bInheritHandle, dwProcessId);

                    if (HANDLE res; DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &res, dwDesiredAccess, bInheritHandle, 0))
                        return res;

                    return {};
                }
                return hook->call_original(dwDesiredAccess, bInheritHandle, dwProcessId);
            });
            s_hook = std::dynamic_pointer_cast<hooks::base_untyped_hook>(std::move(hook));

            logging::I("{} 已通过 import_hook 启用", LogTag);

        } else {
            auto hook = std::make_shared<hooks::direct_hook<decltype(OpenProcess)>>("kernel32.dll!OpenProcess (direct, redirect_openprocess)", OpenProcess);
            hook->set_detour([hook = hook.get()](DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)->HANDLE {
                if (dwProcessId == GetCurrentProcessId()) {
                    if (s_silenceSet.emplace(GetCurrentThreadId()).second)
                        logging::I("{} 线程 {} 调用了 OpenProcess(0x{:08X}, {}, {}), 正在重定向到 DuplicateHandle", LogTag, GetCurrentThreadId(), dwDesiredAccess, bInheritHandle, dwProcessId);

                    if (HANDLE res; DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &res, dwDesiredAccess, bInheritHandle, 0))
                        return res;

                    return {};
                }
                return hook->call_original(dwDesiredAccess, bInheritHandle, dwProcessId);
            });
            s_hook = std::dynamic_pointer_cast<hooks::base_untyped_hook>(std::move(hook));

            logging::I("{} 已通过 direct_hook 启用", LogTag);
        }

        //std::thread([]() {
        //    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
        //    for (const auto to = GetTickCount64() + 3000; GetTickCount64() < to;)
        //        s_hook->assert_dominance();
        //}).detach();

    } else {
        if (s_hook) {
            logging::I("{} 正在禁用 OpenProcess 挂钩", LogTag);
            s_hook.reset();
        }
    }
}

void xivfixes::backup_userdata_save(bool bApply) {
    static const char* LogTag = "[xivfixes:backup_userdata_save]";
    static std::optional<hooks::import_hook<decltype(CreateFileW)>> s_hookCreateFileW;
    static std::optional<hooks::import_hook<decltype(CloseHandle)>> s_hookCloseHandle;
    static std::map<HANDLE, std::pair<std::filesystem::path, std::filesystem::path>> s_handles;
    static std::mutex s_mtx;

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("backup_userdata_save")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }

        s_hookCreateFileW.emplace("kernel32.dll!CreateFileW (import, backup_userdata_save)", "kernel32.dll", "CreateFileW", 0);
        s_hookCloseHandle.emplace("kernel32.dll!CloseHandle (import, backup_userdata_save)", "kernel32.dll", "CloseHandle", 0);

        s_hookCreateFileW->set_detour([](LPCWSTR lpFileName,
            DWORD dwDesiredAccess,
            DWORD dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD dwCreationDisposition,
            DWORD dwFlagsAndAttributes,
            HANDLE hTemplateFile) noexcept {

            if (dwDesiredAccess != GENERIC_WRITE)
                return s_hookCreateFileW->call_original(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

            auto path = std::filesystem::path(lpFileName);
            const auto ext = unicode::convert<std::string>(path.extension().wstring(), &unicode::lower);
            if (ext != ".dat" && ext != ".cfg")
                return s_hookCreateFileW->call_original(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

            // Resolve any symbolic links or shenanigans in the chain so that we'll always be working with a canonical
            // file. If there's an error getting the canonical path, fall back to default behavior and ignore our
            // fancy logic. We use weakly_canonical here so that we don't run into issues if `path` does not exist.
            std::error_code ec;
            path = weakly_canonical(path, ec);
            if (ec)
                return s_hookCreateFileW->call_original(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

            std::filesystem::path temporaryPath = path;
            temporaryPath.replace_extension(std::format(L"{}.new.{:X}.{:X}", path.extension().c_str(), std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count(), GetCurrentProcessId()));
            const auto handle = s_hookCreateFileW->call_original(temporaryPath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, dwShareMode, lpSecurityAttributes, CREATE_ALWAYS, dwFlagsAndAttributes, hTemplateFile);
            if (handle == INVALID_HANDLE_VALUE)
                return handle;

            const auto lock = std::lock_guard(s_mtx);
            s_handles.try_emplace(handle, std::move(temporaryPath), std::move(path));
            
            return handle;
        });

        s_hookCloseHandle->set_detour([](HANDLE handle) noexcept {
            const auto lock = std::lock_guard(s_mtx);
            if (const auto it = s_handles.find(handle); it != s_handles.end()) {
                std::filesystem::path tempPath(std::move(it->second.first));
                std::filesystem::path finalPath(std::move(it->second.second));
                s_handles.erase(it);

                if (exists(finalPath)) {
                    std::filesystem::path oldPath = finalPath;
                    oldPath.replace_extension(finalPath.extension().wstring() + L".old");
                    try {
                        rename(finalPath, oldPath);
                    } catch (const std::exception& e) {
                        logging::E("{0} 无法将 {1} 重命名为 {2}: {3}",
                            LogTag,
                            unicode::convert<std::string>(finalPath.c_str()),
                            unicode::convert<std::string>(oldPath.c_str()),
                            e.what());
                    }
                }

                const auto pathwstr = finalPath.wstring();
                std::vector<char> renameInfoBuf(sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * pathwstr.size() + 2);
                auto& renameInfo = *reinterpret_cast<FILE_RENAME_INFO*>(&renameInfoBuf[0]);
                renameInfo.ReplaceIfExists = true;
                renameInfo.FileNameLength = static_cast<DWORD>(pathwstr.size() * 2);
                memcpy(renameInfo.FileName, &pathwstr[0], renameInfo.FileNameLength);
                if (!SetFileInformationByHandle(handle, FileRenameInfo, &renameInfoBuf[0], static_cast<DWORD>(renameInfoBuf.size()))) {
                    logging::E("{0} 无法将 {1} 重命名为 {2}: Win32 错误 {3}(0x{3})",
                        LogTag,
                        unicode::convert<std::string>(tempPath.c_str()),
                        unicode::convert<std::string>(finalPath.c_str()),
                        GetLastError());
                }
            }
            return s_hookCloseHandle->call_original(handle);
        });

        logging::I("{} 已启用", LogTag);
    } else {
        if (s_hookCreateFileW) {
            logging::I("{} 正在禁用 CreateFileW 挂钩", LogTag);
            s_hookCreateFileW.reset();
        }
    }
}

void xivfixes::prevent_icmphandle_crashes(bool bApply) {
    static const char* LogTag = "[xivfixes:prevent_icmphandle_crashes]";

    static std::optional<hooks::import_hook<decltype(IcmpCloseHandle)>> s_hookIcmpCloseHandle;

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("prevent_icmphandle_crashes")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }

        s_hookIcmpCloseHandle.emplace("iphlpapi.dll!IcmpCloseHandle (import, prevent_icmphandle_crashes)", "iphlpapi.dll", "IcmpCloseHandle", 0);

        s_hookIcmpCloseHandle->set_detour([](HANDLE IcmpHandle) noexcept {
            // this is exactly how windows behaves, however calling IcmpCloseHandle with
            // an invalid handle will segfault on wine...
            if (IcmpHandle == INVALID_HANDLE_VALUE) {
                logging::W("{} IcmpCloseHandle 收到了 INVALID_HANDLE_VALUE", LogTag);
                return FALSE;
            }
            return s_hookIcmpCloseHandle->call_original(IcmpHandle);
        });

        logging::I("{} 已启用", LogTag);
    }
    else {
        if (s_hookIcmpCloseHandle) {
            logging::I("{} 已禁用", LogTag);
            s_hookIcmpCloseHandle.reset();
        }
    }
}

void xivfixes::symbol_load_patches(bool bApply) {
    static const char* LogTag = "[xivfixes:symbol_load_patches]";

    static std::optional<hooks::import_hook<decltype(SymInitialize)>> s_hookSymInitialize;
    static PVOID s_dllNotificationCookie = nullptr;

    static const auto RemoveFullPathPdbInfo = [](const utils::loaded_module& mod) {
        const auto ddva = mod.data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG).VirtualAddress;
        if (!ddva)
            return;

        const auto& ddir = mod.ref_as<IMAGE_DEBUG_DIRECTORY>(ddva);
        if (ddir.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            // The Visual C++ debug information.
            // Ghidra calls it "DotNetPdbInfo".
            static constexpr DWORD DotNetPdbInfoSignatureValue = 0x53445352;
            struct DotNetPdbInfo {
                DWORD Signature; // RSDS
                GUID Guid;
                DWORD Age;
                char PdbPath[1];
            };

            const auto& pdbref = mod.ref_as<DotNetPdbInfo>(ddir.AddressOfRawData);
            if (pdbref.Signature == DotNetPdbInfoSignatureValue) {
                const auto pathSpan = std::string_view(pdbref.PdbPath, strlen(pdbref.PdbPath));
                const auto pathWide = unicode::convert<std::wstring>(pathSpan);
                std::wstring windowsDirectory(GetWindowsDirectoryW(nullptr, 0) + 1, L'\0');
                windowsDirectory.resize(
                    GetWindowsDirectoryW(windowsDirectory.data(), static_cast<UINT>(windowsDirectory.size())));
                if (!PathIsRelativeW(pathWide.c_str()) && !PathIsSameRootW(windowsDirectory.c_str(), pathWide.c_str())) {
                    utils::memory_tenderizer pathOverwrite(&pdbref.PdbPath, pathSpan.size(), PAGE_READWRITE);
                    auto sep = std::find(pathSpan.rbegin(), pathSpan.rend(), '/');
                    if (sep == pathSpan.rend())
                        sep = std::find(pathSpan.rbegin(), pathSpan.rend(), '\\');
                    if (sep != pathSpan.rend()) {
                        logging::I(
                            "{} 正在移除 pdb 路径中的目录部分: {} -> {}",
                            LogTag,
                            pathSpan,
                            &*sep + 1);
                        memmove(const_cast<char*>(pathSpan.data()), &*sep + 1, sep - pathSpan.rbegin() + 1);
                    } else {
                        logging::I("{} 保持 pdb 路径不变: {}", LogTag, pathSpan);
                    }
                } else {
                    logging::I("{} 保持 pdb 路径不变: {}", LogTag, pathSpan);
                }
            } else {
                logging::I("{} CODEVIEW 结构签名不匹配, 当前值为 {:08X}", LogTag, pdbref.Signature);
            }
        } else {
            logging::I("{} 调试目录类型 {} 不受支持", LogTag, ddir.Type);
        }
    };

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("symbol_load_patches")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }

        for (const auto& mod : utils::loaded_module::all_modules())
           RemoveFullPathPdbInfo(mod); 

        if (!s_dllNotificationCookie) {
            const auto res = LdrRegisterDllNotification(
                0,
                [](ULONG notiReason, const LDR_DLL_NOTIFICATION_DATA* pData, void* /* context */) {
                    if (notiReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
                        RemoveFullPathPdbInfo(pData->Loaded.DllBase);
                },
                nullptr,
                &s_dllNotificationCookie);

            if (res != STATUS_SUCCESS) {
                logging::E("{} LdrRegisterDllNotification 失败: 0x{:08X}", LogTag, res);
                s_dllNotificationCookie = nullptr;
            }
        }

        s_hookSymInitialize.emplace("dbghelp.dll!SymInitialize (import, symbol_load_patches)", "dbghelp.dll", "SymInitialize", 0);
        s_hookSymInitialize->set_detour([](HANDLE hProcess, PCSTR UserSearchPath, BOOL fInvadeProcess) noexcept {
            logging::I("{} 已拦截 SymInitialize", LogTag);
            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        });

        logging::I("{} 已启用", LogTag);
    }
    else {
        if (s_hookSymInitialize) {
            logging::I("{} 已禁用", LogTag);
            s_hookSymInitialize.reset();
        }

        if (s_dllNotificationCookie) {
            (void)LdrUnregisterDllNotification(s_dllNotificationCookie);
            s_dllNotificationCookie = nullptr;
        }
    }
}

void xivfixes::disable_game_debugging_protection(bool bApply) {
    static const char* LogTag = "[xivfixes:disable_game_debugging_protection]";
    static std::optional<hooks::import_hook<decltype(IsDebuggerPresent)>> s_hookIsDebuggerPresent;

    if (bApply) {
        if (!g_startInfo.BootEnabledGameFixes.contains("disable_game_debugging_protection")) {
            logging::I("{} 已通过环境变量关闭", LogTag);
            return;
        }

        s_hookIsDebuggerPresent.emplace("kernel32.dll!IsDebuggerPresent", "kernel32.dll", "IsDebuggerPresent", 0);
        s_hookIsDebuggerPresent->set_detour([]() { return false; });
        logging::I("{} 已启用", LogTag);
    } else {
        if (s_hookIsDebuggerPresent) {
            logging::I("{} 已禁用", LogTag);
            s_hookIsDebuggerPresent.reset();
        }
    }
}

void xivfixes::apply_all(bool bApply) {
    for (const auto& [taskName, taskFunction] : std::initializer_list<std::pair<const char*, void(*)(bool)>>
        {
            { "unhook_dll", &unhook_dll },
            { "prevent_devicechange_crashes", &prevent_devicechange_crashes },
            { "disable_game_openprocess_access_check", &disable_game_openprocess_access_check },
            { "redirect_openprocess", &redirect_openprocess },
            { "backup_userdata_save", &backup_userdata_save },
            { "prevent_icmphandle_crashes", &prevent_icmphandle_crashes },
            { "symbol_load_patches", &symbol_load_patches },
            { "disable_game_debugging_protection", &disable_game_debugging_protection },
        }
        ) {
        try {
            taskFunction(bApply);

        } catch (const std::exception& e) {
            if (bApply)
                logging::W("启用修复项 [{}] 时出错: {}", taskName, e.what());
            else
                logging::W("停用修复项 [{}] 时出错: {}", taskName, e.what());

            continue;
        }

        if (bApply)
            logging::I("修复项 [{}] 已启用", taskName);
        else
            logging::I("修复项 [{}] 已停用", taskName);
    }
}
