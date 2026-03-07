#ifndef REGAPIWRAP_HPP
#define REGAPIWRAP_HPP

#include <windows.h>

#define HOOK_FUNC(func) \
static auto Real##func = func; \
decltype(func) Hook##func

// Ex 系列 ANSI 版本函数
HOOK_FUNC(RegCreateKeyExA);
HOOK_FUNC(RegOpenKeyExA);
HOOK_FUNC(RegQueryValueExA);
HOOK_FUNC(RegSetValueExA);
HOOK_FUNC(RegEnumKeyExA);

// 旧版 Unicode API 钩子函数
HOOK_FUNC(RegCreateKeyW);
HOOK_FUNC(RegOpenKeyW);
HOOK_FUNC(RegQueryValueW);
HOOK_FUNC(RegSetValueW);
HOOK_FUNC(RegEnumKeyW);

// 旧版 ANSI API 钩子函数
HOOK_FUNC(RegCreateKeyA);
HOOK_FUNC(RegOpenKeyA);
HOOK_FUNC(RegQueryValueA);
HOOK_FUNC(RegSetValueA);
HOOK_FUNC(RegDeleteKeyA);
HOOK_FUNC(RegDeleteValueA);
HOOK_FUNC(RegEnumKeyA);
HOOK_FUNC(RegEnumValueA);
HOOK_FUNC(RegQueryInfoKeyA);

#undef HOOK_FUNC

#endif // REGAPIWRAP_HPP