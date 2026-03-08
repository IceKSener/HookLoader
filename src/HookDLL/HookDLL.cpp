#include <stdio.h>
#include <windows.h>
#include <MinHook.h>

#include "RegForm.hpp"
#include "Common.hpp"
#include "HookDLL/RegAPI.hpp"
#include "HookDLL/RegAPIWrap.hpp"

using namespace std;

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
        
#define ERR_HOOK(func) (MH_CreateHook((LPVOID)func, (LPVOID)Hook##func, (LPVOID*)&Real##func) != MH_OK)
        // 创建所有注册表钩子
        if (
            // 注册表基础API
            ERR_HOOK(RegCreateKeyExW) ||
            ERR_HOOK(RegOpenKeyExW) ||
            ERR_HOOK(RegQueryValueExW) ||
            ERR_HOOK(RegSetValueExW) ||
            ERR_HOOK(RegCloseKey) ||
            ERR_HOOK(RegDeleteKeyExW) ||
            ERR_HOOK(RegDeleteValueW) ||
            ERR_HOOK(RegEnumKeyExW) ||
            ERR_HOOK(RegEnumValueW) ||
            ERR_HOOK(RegQueryInfoKeyW) ||

            // 兼容旧API
            ERR_HOOK(RegCreateKeyExA) ||
            ERR_HOOK(RegCreateKeyW) ||
            ERR_HOOK(RegCreateKeyA) ||
            ERR_HOOK(RegOpenKeyExA) ||
            ERR_HOOK(RegOpenKeyW) ||
            ERR_HOOK(RegOpenKeyA) ||
            ERR_HOOK(RegQueryValueExA) ||
            ERR_HOOK(RegQueryValueW) ||
            ERR_HOOK(RegQueryValueA) ||
            ERR_HOOK(RegSetValueExA) ||
            ERR_HOOK(RegSetValueW) ||
            ERR_HOOK(RegSetValueA) ||
            ERR_HOOK(RegDeleteKeyExA) ||
            ERR_HOOK(RegDeleteKeyW) ||
            ERR_HOOK(RegDeleteKeyA) ||
            ERR_HOOK(RegDeleteValueA) ||
            ERR_HOOK(RegEnumKeyExA) ||
            ERR_HOOK(RegEnumKeyW) ||
            ERR_HOOK(RegEnumKeyA) ||
            ERR_HOOK(RegEnumValueA) ||

            ERR_HOOK(CreateProcessW)
        )
        {
            wprintf(L"[HookDLL] MH_CreateHook failed\n");
            return FALSE;
        }
#undef ERR_HOOK

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