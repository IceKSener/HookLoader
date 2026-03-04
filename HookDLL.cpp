#include <stdio.h>
#include <errno.h>
#include <windows.h>
#include <MinHook.h>
#include <Shlwapi.h>
// #pragma comment(lib, "Shlwapi.lib")

// 原函数指针
auto RealRegCreateKeyExW = RegCreateKeyExW;
auto RealRegOpenKeyExW = RegOpenKeyExW;
auto RealRegQueryValueExW = RegQueryValueExW;
auto RealRegSetValueExW = RegSetValueExW;
auto RealRegCloseKey = RegCloseKey;
auto RealRegDeleteKeyW = RegDeleteKeyW;
auto RealRegDeleteValueW = RegDeleteValueW;
auto RealRegEnumKeyExW = RegEnumKeyExW;
auto RealRegEnumValueW = RegEnumValueW;
auto RealRegQueryInfoKeyW = RegQueryInfoKeyW;

auto RealCreateProcessW = CreateProcessW;

FILE* logger =  NULL;

CRITICAL_SECTION g_cs;

void WriteLog(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wchar_t buff[10240];
    vswprintf(buff, format, args);
    EnterCriticalSection(&g_cs);
    wsprintf(L"%s",buff);
    if(logger!=NULL){
        fputws(buff, logger);
        fflush(logger);
    }
    LeaveCriticalSection(&g_cs);
    va_end(args);
}

// 钩子函数定义

// RegCreateKeyExW
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    WriteLog(L"[RegCreateKeyExW] hKey=%p, SubKey=%s\n", hKey, lpSubKey ? lpSubKey : L"(null)");
    LONG ret = RealRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    WriteLog(L"    -> ret=%ld, phkResult=%p, Disposition=0x%p\n", ret, *phkResult, lpdwDisposition ? *lpdwDisposition : 0);
    return ret;
}

// RegOpenKeyExW
LONG WINAPI HookRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    WriteLog(L"[RegOpenKeyExW] hKey=%p, SubKey=%s\n", hKey, lpSubKey ? lpSubKey : L"(null)");
    LONG ret = RealRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    WriteLog(L"    -> ret=%ld, phkResult=%p\n", ret, *phkResult);
    return ret;
}

// RegQueryValueExW
LONG WINAPI HookRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    WriteLog(L"[RegQueryValueExW] hKey=%p, ValueName=%s\n", hKey, lpValueName ? lpValueName : L"(null)");
    LONG ret = RealRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    WriteLog(L"    -> ret=%ld\n", ret);
    return ret;
}

// RegSetValueExW
LONG WINAPI HookRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    WriteLog(L"[RegSetValueExW] hKey=%p, ValueName=%s, Reserved=0x%X, Type=0x%X, DataSize=%d\n",
             hKey, lpValueName ? lpValueName : L"(null)", Reserved, dwType, cbData);
    LONG ret = RealRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    WriteLog(L"    -> ret=%ld\n", ret);
    return ret;
}

// RegCloseKey
LONG WINAPI HookRegCloseKey(HKEY hKey)
{
    WriteLog(L"[RegCloseKey] hKey=%p\n", hKey);
    LONG ret = RealRegCloseKey(hKey);
    WriteLog(L"    -> ret=%ld\n", ret);
    return ret;
}

// RegDeleteKeyW
LONG WINAPI HookRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
    WriteLog(L"[RegDeleteKeyW] hKey=%p, SubKey=%s\n", hKey, lpSubKey ? lpSubKey : L"(null)");
    LONG ret = RealRegDeleteKeyW(hKey, lpSubKey);
    WriteLog(L"    -> ret=%ld\n", ret);
    return ret;
}

// RegDeleteValueW
LONG WINAPI HookRegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    WriteLog(L"[RegDeleteValueW] hKey=%p, ValueName=%s\n", hKey, lpValueName ? lpValueName : L"(null)");
    LONG ret = RealRegDeleteValueW(hKey, lpValueName);
    WriteLog(L"    -> ret=%ld\n", ret);
    return ret;
}

// RegEnumKeyExW
LONG WINAPI HookRegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime)
{
    WriteLog(L"[RegEnumKeyExW] hKey=%p, Index=%d\n", hKey, dwIndex);
    LONG ret = RealRegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved, lpClass, lpcClass, lpftLastWriteTime);
    WriteLog(L"    -> ret=%ld, Name=%s\n", ret, lpName ? lpName : L"(null)");
    return ret;
}

// RegEnumValueW
LONG WINAPI HookRegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    WriteLog(L"[RegEnumValueW] hKey=%p, Index=%d\n", hKey, dwIndex);
    LONG ret = RealRegEnumValueW(hKey, dwIndex, lpValueName, lpcValueName, lpReserved, lpType, lpData, lpcbData);
    WriteLog(L"    -> ret=%ld, ValueName=%s\n", ret, lpValueName ? lpValueName : L"(null)");
    return ret;
}

// RegQueryInfoKeyW
LONG WINAPI HookRegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, FILETIME* lpftLastWriteTime)
{
    WriteLog(L"[RegQueryInfoKeyW] hKey=%p\n", hKey);
    LONG ret = RealRegQueryInfoKeyW(hKey, lpClass, lpcClass, lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    WriteLog(L"    -> ret=%ld, SubKeys=%u, Values=%u\n", ret, lpcSubKeys ? *lpcSubKeys : 0, lpcValues ? *lpcValues : 0);
    return ret;
}

// CreateProcessW（非注册表操作，但原代码已有）
BOOL WINAPI HookCreateProcessW(LPCWSTR lpApp, LPWSTR lpCmd, LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
                               BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    WriteLog(L"[CreateProcessW] CmdLine=%s\n", lpCmd ? lpCmd : L"(null)");
    DWORD flags = dwFlags | CREATE_SUSPENDED;
    BOOL ret = RealCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bInherit, flags, lpEnv, lpDir, lpSI, lpPI);
    if (!ret)
    {
        WriteLog(L"    -> CreateProcess failed, error=%d\n", GetLastError());
        return FALSE;
    }
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleW(L"HookDLL.dll"), dllPath, MAX_PATH);
    SIZE_T size = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(lpPI->hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        WriteLog(L"    -> VirtualAllocEx failed, error=%d\n", GetLastError());
        ResumeThread(lpPI->hThread);
        return ret;
    }
    WriteProcessMemory(lpPI->hProcess, pRemoteBuf, dllPath, size, NULL);
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hRemoteThread = CreateRemoteThread(lpPI->hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (hRemoteThread)
    {
        WaitForSingleObject(hRemoteThread, INFINITE);
        CloseHandle(hRemoteThread);
    }
    else
        WriteLog(L"    -> CreateRemoteThread failed, error=%d\n", GetLastError());
    VirtualFreeEx(lpPI->hProcess, pRemoteBuf, 0, MEM_RELEASE);
    ResumeThread(lpPI->hThread);
    WriteLog(L"    -> Child process resumed.\n");
    return ret;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        logger = fopen("Z:\\log.txt", "a");
        if(!logger){
            char buffer[256];
            strerror_s(buffer, sizeof(buffer), errno);
            printf("fopen failed: %s\n", buffer);
        }
        // 初始化 MinHook
        if (MH_Initialize() != MH_OK)
        {
            wprintf(L"MH_Initialize failed\n");
            return FALSE;
        }

        // 创建所有注册表钩子
        if (
            MH_CreateHook((LPVOID)RegCreateKeyExW, (LPVOID)HookRegCreateKeyExW, (LPVOID*)&RealRegCreateKeyExW) != MH_OK ||
            MH_CreateHook((LPVOID)RegOpenKeyExW, (LPVOID)HookRegOpenKeyExW, (LPVOID*)&RealRegOpenKeyExW) != MH_OK ||
            MH_CreateHook((LPVOID)RegQueryValueExW, (LPVOID)HookRegQueryValueExW, (LPVOID*)&RealRegQueryValueExW) != MH_OK ||
            MH_CreateHook((LPVOID)RegSetValueExW, (LPVOID)HookRegSetValueExW, (LPVOID*)&RealRegSetValueExW) != MH_OK ||
            MH_CreateHook((LPVOID)RegCloseKey, (LPVOID)HookRegCloseKey, (LPVOID*)&RealRegCloseKey) != MH_OK ||
            MH_CreateHook((LPVOID)RegDeleteKeyW, (LPVOID)HookRegDeleteKeyW, (LPVOID*)&RealRegDeleteKeyW) != MH_OK ||
            MH_CreateHook((LPVOID)RegDeleteValueW, (LPVOID)HookRegDeleteValueW, (LPVOID*)&RealRegDeleteValueW) != MH_OK ||
            MH_CreateHook((LPVOID)RegEnumKeyExW, (LPVOID)HookRegEnumKeyExW, (LPVOID*)&RealRegEnumKeyExW) != MH_OK ||
            MH_CreateHook((LPVOID)RegEnumValueW, (LPVOID)HookRegEnumValueW, (LPVOID*)&RealRegEnumValueW) != MH_OK ||
            MH_CreateHook((LPVOID)RegQueryInfoKeyW, (LPVOID)HookRegQueryInfoKeyW, (LPVOID*)&RealRegQueryInfoKeyW) != MH_OK ||
            MH_CreateHook((LPVOID)CreateProcessW, (LPVOID)HookCreateProcessW, (LPVOID*)&RealCreateProcessW) != MH_OK
        )
        {
            wprintf(L"MH_CreateHook failed\n");
            return FALSE;
        }

        // 启用钩子
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            wprintf(L"MH_EnableHook failed\n");
            return FALSE;
        }

        wprintf(L"HookDLL loaded into process %d\n", GetCurrentProcessId());
        break;

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        fclose(logger);
        DeleteCriticalSection(&g_cs);
        break;
    }
    return TRUE;
}