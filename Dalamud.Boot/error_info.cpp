#include "error_info.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

DalamudBootError::DalamudBootError(DalamudBootErrorDescription dalamudErrorDescription, long hresult) noexcept
    : m_dalamudErrorDescription(dalamudErrorDescription)
    , m_hresult(hresult) {
}

DalamudBootError::DalamudBootError(DalamudBootErrorDescription dalamudErrorDescription) noexcept
    : DalamudBootError(dalamudErrorDescription, E_FAIL) {
}

const char* DalamudBootError::describe() const {
    switch (m_dalamudErrorDescription) {
        case DalamudBootErrorDescription::ModuleResourceLoadFail:
            return "资源加载失败";
        case DalamudBootErrorDescription::ModuleResourceVersionReadFail:
            return "读取版本信息失败";
        case DalamudBootErrorDescription::ModuleResourceVersionSignatureFail:
            return "检测到无效的版本信息";
        default:
            return "无可用说明";
    }
}
