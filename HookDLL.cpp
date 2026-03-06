#include <stdio.h>
#include <errno.h>
#include <windows.h>
#include <MinHook.h>
#include <Shlwapi.h>

#include "RegForm.hpp"
#include "Common.hpp"

using namespace std;
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

CRITICAL_SECTION g_cs;

BOOL g_enableHook =  FALSE;
wchar_t g_pipeName[128]={0};
HANDLE g_hPipe = INVALID_HANDLE_VALUE;

void WriteLog(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wchar_t buff[10240];
    vswprintf(buff, format, args);
    EnterCriticalSection(&g_cs);
    wprintf(L"%s",buff);
    LeaveCriticalSection(&g_cs);
    va_end(args);
}

// 发送请求并接收响应（线程安全）
BOOL SendRequestAndReceive(const RegRequest& req, RegResponse& res)
{
    if (g_hPipe == INVALID_HANDLE_VALUE) return FALSE;

    EnterCriticalSection(&g_cs);
    DWORD cbWritten, cbRead;
    BOOL success = WriteFile(g_hPipe, &req, sizeof(RegRequest), &cbWritten, NULL);
    if (!success || cbWritten != sizeof(RegRequest)) {
        WriteLog(L"[HookDLL] WriteFile to pipe failed, error=%d\n", GetLastError());
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }

    success = ReadFile(g_hPipe, &res, sizeof(RegResponse), &cbRead, NULL);
    if (!success || cbRead != sizeof(RegResponse)) {
        WriteLog(L"[HookDLL] ReadFile from pipe failed, error=%d\n", GetLastError());
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }

    LeaveCriticalSection(&g_cs);
    return TRUE;
}

// 钩子函数定义

// RegCreateKeyExW
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_CREATEKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.createKey.path, lpSubKey);
    req.createKey.dwOptions = dwOptions;
    req.createKey.samDesired = samDesired;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (phkResult) *phkResult = res.hKey;
    if (lpdwDisposition) *lpdwDisposition = res.createKey.disposition;

    return res.ret;
}

// RegOpenKeyExW
LONG WINAPI HookRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_OPENKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.openKey.path, lpSubKey);
    req.openKey.samDesired = samDesired;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (phkResult) *phkResult = res.hKey;

    return res.ret;
}

// RegQueryValueExW
LONG WINAPI HookRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.queryValue.valueName, lpValueName);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (lpType) *lpType = res.queryValue.type;
    if (lpData && lpcbData) {
        DWORD copyLen = (*lpcbData<res.queryValue.dataLen)? *lpcbData: res.queryValue.dataLen;
        memcpy(lpData, res.queryValue.data, copyLen);
        *lpcbData = copyLen;
    } else if (lpcbData) {
        *lpcbData = res.queryValue.dataLen;
    }

    return res.ret;
}

// RegSetValueExW
LONG WINAPI HookRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_SETVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.setValue.valueName, lpValueName);
    req.setValue.type = dwType;
    req.setValue.dataLen = (cbData<(DWORD)sizeof(req.setValue.data))? cbData: (DWORD)sizeof(req.setValue.data);
    memcpy(req.setValue.data, lpData, req.setValue.dataLen);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;
        
    return res.ret;
}

// RegCloseKey
LONG WINAPI HookRegCloseKey(HKEY hKey)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_CLOSEKEY;
    req.hKey = hKey;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;
    
    return res.ret;
}

// RegDeleteKeyW
LONG WINAPI HookRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_DELETEKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.deleteKey.path, lpSubKey);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    return res.ret;
}

// RegDeleteValueW
LONG WINAPI HookRegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_DELETEVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.deleteValue.valueName, lpValueName);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    return res.ret;
}

// RegEnumKeyExW
LONG WINAPI HookRegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_ENUMKEY;
    req.hKey = hKey;
    req.enumInfo.index = dwIndex;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret == ERROR_SUCCESS && lpName && lpcName) {
        wcsncpy(lpName, res.enumKey.name, *lpcName - 1);
        lpName[*lpcName - 1] = L'\0';
        *lpcName = (DWORD)wcslen(lpName) + 1;
    }

    return res.ret;
}

// RegEnumValueW
LONG WINAPI HookRegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_ENUMVALUE;
    req.hKey = hKey;
    req.enumInfo.index = dwIndex;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret == ERROR_SUCCESS) {
        if (lpValueName && lpcValueName) {
            wcsncpy(lpValueName, res.enumValue.valueName, *lpcValueName - 1);
            lpValueName[*lpcValueName - 1] = L'\0';
            *lpcValueName = (DWORD)wcslen(lpValueName) + 1;
        }
        if (lpType) *lpType = res.enumValue.type;
        if (lpData && lpcbData) {
            DWORD copyLen = (*lpcbData<res.enumValue.dataLen)? *lpcbData: res.enumValue.dataLen;
            memcpy(lpData, res.enumValue.data, copyLen);
            *lpcbData = copyLen;
        }
    }
    return res.ret;
}

// RegQueryInfoKeyW
LONG WINAPI HookRegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, FILETIME* lpftLastWriteTime)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYINFOKEY;
    req.hKey = hKey;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret != ERROR_SUCCESS)
        return res.ret;

    // 填充各输出参数（如果指针非空）
    if (lpcSubKeys) *lpcSubKeys = res.queryInfo.subKeys;
    if (lpcMaxSubKeyLen) *lpcMaxSubKeyLen = res.queryInfo.maxSubKeyLen;
    if (lpcMaxClassLen) *lpcMaxClassLen = res.queryInfo.maxClassLen;
    if (lpcValues) *lpcValues = res.queryInfo.values;
    if (lpcMaxValueNameLen) *lpcMaxValueNameLen = res.queryInfo.maxValueNameLen;
    if (lpcMaxValueLen) *lpcMaxValueLen = res.queryInfo.maxValueLen;
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = res.queryInfo.securityDescriptor;
    if (lpftLastWriteTime) *lpftLastWriteTime = res.queryInfo.lastWriteTime;

    // 处理类名
    if (lpClass && lpcClass) {
        // 计算实际需要的字符数（包括 null 终止符）
        size_t required = wcslen(res.queryInfo.className) + 1;
        DWORD bufferSize = *lpcClass;   // 输入时缓冲区的容量（字符数）

        if (bufferSize > 0) {
            wcsncpy(lpClass, res.queryInfo.className, bufferSize - 1);
            lpClass[bufferSize - 1] = L'\0';
        }
        *lpcClass = (DWORD)required;
    }
    else if (lpcClass) {
        // lpClass 为 NULL，仅返回所需大小
        *lpcClass = (DWORD)wcslen(res.queryInfo.className) + 1;
    }

    return ERROR_SUCCESS;
}

// CreateProcessW（非注册表操作，但原代码已有）
BOOL WINAPI HookCreateProcessW(LPCWSTR lpApp, LPWSTR lpCmd, LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
                               BOOL bInherit, DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    WriteLog(L"[HookDLL] CreateProcessW CmdLine=%s\n", lpCmd ? lpCmd : L"(null)");
    DWORD flags = dwFlags | CREATE_SUSPENDED;
    BOOL ret = RealCreateProcessW(lpApp, lpCmd, lpPA, lpTA, bInherit, flags, lpEnv, lpDir, lpSI, lpPI);
    if (!ret)
    {
        WriteLog(L"[HookDLL]  CreateProcess failed, error=%d\n", GetLastError());
        return FALSE;
    }
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleW(L"HookDLL.dll"), dllPath, MAX_PATH);

    // 注入dll
   if(_RemoteCall(lpPI->hProcess, L"kernel32.dll", "LoadLibraryW", dllPath)==_CALL_SUCCESS){
        // 设置管道名
        _RemoteCall(lpPI->hProcess, L"HookDLL.dll", "SetPipeName", g_pipeName);
   }
   
    ResumeThread(lpPI->hThread);
    WriteLog(L"[HookDLL] Child process resumed.\n");
    return ret;
}

extern "C" __declspec(dllexport) DWORD WINAPI SetPipeName(LPCWSTR pipeName)
{
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        wprintf(L"[HookDLL] HookDLL loaded into process %d\n", GetCurrentProcessId());
        EnterCriticalSection(&g_cs);
        wcscpy_s(g_pipeName, pipeName);
        g_hPipe = CreateFileW(
            g_pipeName
            , GENERIC_READ | GENERIC_WRITE
            , 0
            , NULL
            , OPEN_EXISTING
            , 0
            , NULL
        );
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            WriteLog(L"[HookDLL] Failed to connect to pipe %s, error=%d\n", g_pipeName, GetLastError());
            LeaveCriticalSection(&g_cs);
            return 0 ;
        }
        WriteLog(L"[HookDLL] Connected to pipe %s\n", g_pipeName);
        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(g_hPipe, &mode, NULL, NULL);
        
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
            wprintf(L"[HookDLL] MH_CreateHook failed\n");
            return FALSE;
        }

        // 启用钩子
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            wprintf(L"[HookDLL] MH_EnableHook failed\n");
            return FALSE;
        }

        LeaveCriticalSection(&g_cs);
    }
    return 0;
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        // 初始化 MinHook
        if (MH_Initialize() != MH_OK)
        {
            wprintf(L"[HookDLL] MH_Initialize failed\n");
            return FALSE;
        }
        break;

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        if(g_hPipe!=INVALID_HANDLE_VALUE){
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
        DeleteCriticalSection(&g_cs);
        break;
    }
    return TRUE;
}