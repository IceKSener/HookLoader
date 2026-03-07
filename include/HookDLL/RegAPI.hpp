#ifndef REGAPI_HPP
#define REGAPI_HPP

#include <windows.h>

#define HOOK_FUNC(func) \
static auto Real##func = func; \
decltype(func) Hook##func

// 基础API

HOOK_FUNC(RegCreateKeyExW);
HOOK_FUNC(RegOpenKeyExW);
HOOK_FUNC(RegQueryValueExW);
HOOK_FUNC(RegSetValueExW);
HOOK_FUNC(RegCloseKey);
HOOK_FUNC(RegDeleteKeyW);
HOOK_FUNC(RegDeleteValueW);
HOOK_FUNC(RegEnumKeyExW);
HOOK_FUNC(RegEnumValueW);
HOOK_FUNC(RegQueryInfoKeyW);

#undef HOOK_FUNC

#endif // REGAPI_HPP