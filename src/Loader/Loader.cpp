#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <map>
#include <string>

#include "RegForm.hpp"
#include "VirtualRegistry.h"
#include "Common.hpp"

using namespace std;

VirtualRegistry virReg;

// 用于维护每个子进程的注册表句柄
CRITICAL_SECTION g_HandleCs;
static wchar_t g_pipeName[128];
BOOL g_Running = true;

DWORD WINAPI ClientThread(LPVOID lpParam){
    HANDLE hPipe = (HANDLE)lpParam;
    DWORD pid = 0;
    GetNamedPipeClientProcessId(hPipe, &pid);
    
    RegRequest req;
    RegResponse res;
    while (g_Running)
    {
        // 读取请求
        if (!ReadFileSafe(hPipe, &req, sizeof(req))) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                wprintf(L"[Loader] Client %u Read Pipe error: %d\n", pid, GetLastError());
            }
            break;
        }
        
        switch (req.op)
        {
            case REG_OP_CREATEKEY: {
                wprintf(L"[Reg] CreateKey\t%s\\%s\n", virReg.GetPath(req.hKey).c_str(), req.createKey.path);
                res.ret = virReg.CreateKey(req.hKey, req.createKey.path, res.hKey, res.createKey.disposition);
                break;
            }
            case REG_OP_OPENKEY: {
                wprintf(L"[Reg] OpenKey\t%s\\%s\n", virReg.GetPath(req.hKey).c_str(), req.openKey.path);
                res.ret = virReg.OpenKey(req.hKey, req.openKey.path, res.hKey);
                break;
            }
            case REG_OP_QUERYVALUE: {
                wprintf(L"[Reg] QueryValue\t%s.%s\n", virReg.GetPath(req.hKey).c_str(), req.queryValue.valueName);
                DWORD type;
                std::vector<BYTE> data;
                res.ret = virReg.QueryValue(req.hKey, req.queryValue.valueName, type, data);
                if (res.ret == ERROR_SUCCESS) {
                    res.queryValue.type = type;
                    res.queryValue.dataLen = min((DWORD)data.size(), (DWORD)sizeof(res.queryValue.data));
                    memcpy(res.queryValue.data, data.data(), res.queryValue.dataLen);
                }
                break;
            }
            case REG_OP_SETVALUE: {
                wprintf(L"[Reg] SetValue\t%s.%s\n", virReg.GetPath(req.hKey).c_str(), req.setValue.valueName);
                // wprintf(L"[...] Size=%d\n", req.setValue.dataLen);
                std::vector<BYTE> data(req.setValue.data, req.setValue.data + req.setValue.dataLen);
                // wprintf(L"[...] data Size=%d\n", data.size());
                res.ret = virReg.SetValue(req.hKey, req.setValue.valueName, req.setValue.type, data);
                break;
            }
            case REG_OP_CLOSEKEY: {
                wprintf(L"[Reg] CloseKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                res.ret = virReg.CloseKey(req.hKey);
                break;
            }
            case REG_OP_ENUMKEY: {
                wprintf(L"[Reg] EnumKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                std::wstring name;
                res.ret = virReg.EnumKey(req.hKey, req.enumInfo.index, name);
                if (res.ret == ERROR_SUCCESS) {
                    wcsncpy_s(res.enumKey.name, name.c_str(), _TRUNCATE);
                }
                break;
            }
            case REG_OP_ENUMVALUE: {
                wprintf(L"[Reg] EnumValue\t%s\n", virReg.GetPath(req.hKey).c_str());
                std::wstring valueName;
                std::vector<BYTE> data;
                res.ret = virReg.EnumValue(req.hKey, req.enumInfo.index, valueName, res.enumValue.type, data);
                if (res.ret == ERROR_SUCCESS) {
                    wcsncpy_s(res.enumValue.valueName, valueName.c_str(), _TRUNCATE);
                    res.enumValue.dataLen = min((DWORD)data.size(), (DWORD)sizeof(res.enumValue.data));
                    memcpy(res.enumValue.data, data.data(), res.enumValue.dataLen);
                }
                break;
            }
            case REG_OP_QUERYINFOKEY: {
                wprintf(L"[Reg] QueryInfo\t%s\n", virReg.GetPath(req.hKey).c_str());
                std::wstring className;
                res.ret = virReg.QueryInfoKey(req.hKey,
                    res.queryInfo.subKeys,
                    res.queryInfo.maxSubKeyLen,
                    res.queryInfo.maxClassLen,
                    res.queryInfo.values,
                    res.queryInfo.maxValueNameLen,
                    res.queryInfo.maxValueLen,
                    res.queryInfo.securityDescriptor,
                    res.queryInfo.lastWriteTime,
                    className);
                if (res.ret == ERROR_SUCCESS) {
                    wcsncpy_s(res.queryInfo.className, className.c_str(), _TRUNCATE);
                }
                break;
            }
            case REG_OP_DELETEKEY: {
                wprintf(L"[Reg] DeleteKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                res.ret = virReg.DeleteKey(req.hKey, req.deleteKey.path);
                break;
            }
            case REG_OP_DELETEVALUE: {
                wprintf(L"[Reg] DeleteValue\t%s\n", virReg.GetPath(req.hKey).c_str());
                res.ret = virReg.DeleteValue(req.hKey, req.deleteValue.valueName);
                break;
            }
            default: {
                res.ret = ERROR_INVALID_HANDLE;
                break;
            }
        }
        if(!WriteFileSafe(hPipe, &res, sizeof(RegResponse)))
        {
            wprintf(L"[Loader] Client %u Write Pipe error: %d\n", pid, GetLastError());
            break;
        }

    }
    return 0;
}

// 命名管道服务端线程
DWORD WINAPI PipeServerThread(LPVOID lpParam)
{
    while(g_Running)
    {
        HANDLE hPipe = CreateNamedPipeW(
            g_pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(RegRequest),
            sizeof(RegResponse),
            0,
            NULL
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            wprintf(L"[PipeServer] CreateNamedPipeW failed: %d\n", GetLastError());
            CloseHandle(hPipe);
            continue;
        }

        if(!ConnectNamedPipe(hPipe, NULL) && GetLastError()!=ERROR_PIPE_CONNECTED)
        {
            wprintf(L"[PipeServer] Named pipe connect failed: %d\n", GetLastError());
            break;
        }

        DWORD clientPid = 0;
        GetNamedPipeClientProcessId(hPipe, &clientPid);
        wprintf(L"[PipeServer] Client connected (PID=%u)\n", clientPid);

        HANDLE hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)hPipe, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);    // 不等待线程，独立运行
        } else {
            wprintf(L"[PipeServer] CreateThread failed: %d\n", GetLastError());
            CloseHandle(hPipe);
        }
    }
    return 0;
}

// 创建命名管道服务端
BOOL InitPipeServer() {
    swprintf(g_pipeName, L"\\\\.\\pipe\\VirtualRegistryPipe%d",GetCurrentProcessId());
    return TRUE;
}

// 注入 DLL 到目标进程
BOOL InjectDll(HANDLE hProcess, const wchar_t* dllPath)
{
    // 注入dll
   const wchar_t* ret = _RemoteCall(hProcess, L"kernel32.dll", "LoadLibraryW", dllPath);
   if(ret != _CALL_SUCCESS){
        wprintf(ret, GetLastError());
        return FALSE;
   }
   ret = _RemoteCall(hProcess, L"HookDLL.dll", "SetPipeName", g_pipeName);
   _putws(L"[Loader] SetPipeName on subprocess");
   if(ret != _CALL_SUCCESS){
        wprintf(ret, GetLastError());
        return FALSE;
   }
    return TRUE;
}

// 主函数
int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        wprintf(L"Usage: loader.exe <command> [args...]\n");
        return 1;
    }

    // 启动命名管道服务端
    if(!InitPipeServer())
    {
        return -1;
    }
    InitializeCriticalSection(&g_HandleCs);
    CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    wchar_t RegFile[] = L"reg.dat";
    if(!virReg.LoadBinary(RegFile)){
        wprintf(L"[Loader] RegFile load failed %d\n", GetLastError());
    }

    // 构建命令行
    wchar_t cmdLine[32768] = {0};
    for (int i = 1; i < argc; i++)
    {
        if (i > 1) wcscat_s(cmdLine, L" ");
        if (wcschr(argv[i], L' ')) {
            wcscat_s(cmdLine, L"\"");
            wcscat_s(cmdLine, argv[i]);
            wcscat_s(cmdLine, L"\"");
        } else {
            wcscat_s(cmdLine, argv[i]);
        }
    }

    // 创建子进程（挂起）
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL,
            cmdLine,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi))
    {
        wprintf(L"[Loader] CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    wprintf(L"[Loader] Process created (PID: %d). Injecting DLL...\n", pi.dwProcessId);

    // 获取当前目录下的 HookDLL.dll 路径
    wchar_t dllPath[MAX_PATH];
    
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    wchar_t* pSlash = wcsrchr(dllPath, L'\\');
    if (pSlash)
        *(pSlash + 1) = L'\0';
    wcscat_s(dllPath, L"HookDLL.dll");
    LoadLibraryW(dllPath);

    // 注入 DLL
    if (!InjectDll(pi.hProcess, dllPath))
    {
        wprintf(L"[Loader] Injection failed, terminating process.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    wprintf(L"[Loader] DLL injected, resuming thread.\n");
    ResumeThread(pi.hThread);

    // 等待子进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    wprintf(L"[Loader] Process exited with code %d\n", exitCode);

    // 清理资源
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteCriticalSection(&g_HandleCs);

    virReg.SaveBinary(RegFile);
    wprintf(L"REG:\n%s", virReg.ToString().c_str());
    // getchar();

    return 0;
}