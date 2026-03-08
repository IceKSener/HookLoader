#include <stdio.h>
#include <vector>
#include <string>
#include <sstream>

#include "RegForm.hpp"
#include "VirtualRegistry.h"
#include "Common.hpp"
#include "Loader/Config.hpp"

using namespace std;

VirtualRegistry virReg;

CRITICAL_SECTION g_LogCs;
static wchar_t g_pipeName[128];
BOOL g_Running = true;

static int WriteLog(LoaderLogLevel level, const wchar_t* format, ...) {
    if (level > Config.logLevel) return -1;
    va_list args;
    va_start(args, format);
    static wchar_t buff[1024*32];
    EnterCriticalSection(&g_LogCs);
    int ret = vswprintf(buff, format, args);
    wprintf(L"%s",buff);
    LeaveCriticalSection(&g_LogCs);
    va_end(args);
    return ret;
}

DWORD WINAPI ClientThread(LPVOID lpParam) {
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
                WriteLog(LOADER_LOG_ERROR , L"[Loader] Client %u Read Pipe error: %d\n", pid, GetLastError());
            }
            break;
        }
        
        switch (req.op)
        {
            case REG_OP_CREATEKEY: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] CreateKey\t%s\\%s\n", virReg.GetPath(req.hKey).c_str(), req.createKey.path);
                res.ret = virReg.CreateKey(req.hKey, req.createKey.path, res.hKey, res.createKey.disposition);
                break;
            }
            case REG_OP_OPENKEY: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] OpenKey\t%s\\%s\n", virReg.GetPath(req.hKey).c_str(), req.openKey.path);
                res.ret = virReg.OpenKey(req.hKey, req.openKey.path, res.hKey);
                break;
            }
            case REG_OP_QUERYVALUE: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] QueryValue\t%s.%s\n", virReg.GetPath(req.hKey).c_str(), req.queryValue.valueName);
                DWORD type;
                vector<BYTE> data;
                res.ret = virReg.QueryValue(req.hKey, req.queryValue.valueName, type, data);
                if (res.ret == ERROR_SUCCESS) {
                    res.queryValue.type = type;
                    res.queryValue.dataLen = min((DWORD)data.size(), (DWORD)sizeof(res.queryValue.data));
                    memcpy(res.queryValue.data, data.data(), res.queryValue.dataLen);
                }
                break;
            }
            case REG_OP_SETVALUE: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] SetValue\t%s.%s\n", virReg.GetPath(req.hKey).c_str(), req.setValue.valueName);
                WriteLog(LOADER_LOG_ALL, L"[...] Size=%d\n", req.setValue.dataLen);
                vector<BYTE> data(req.setValue.data, req.setValue.data + req.setValue.dataLen);
                res.ret = virReg.SetValue(req.hKey, req.setValue.valueName, req.setValue.type, data);
                break;
            }
            case REG_OP_CLOSEKEY: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] CloseKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                res.ret = virReg.CloseKey(req.hKey);
                break;
            }
            case REG_OP_ENUMKEY: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] EnumKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                wstring name;
                res.ret = virReg.EnumKey(req.hKey, req.enumInfo.index, name);
                if (res.ret == ERROR_SUCCESS) {
                    wcsncpy_s(res.enumKey.name, name.c_str(), _TRUNCATE);
                }
                break;
            }
            case REG_OP_ENUMVALUE: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] EnumValue\t%s\n", virReg.GetPath(req.hKey).c_str());
                wstring valueName;
                vector<BYTE> data;
                res.ret = virReg.EnumValue(req.hKey, req.enumInfo.index, valueName, res.enumValue.type, data);
                if (res.ret == ERROR_SUCCESS) {
                    wcsncpy_s(res.enumValue.valueName, valueName.c_str(), _TRUNCATE);
                    res.enumValue.dataLen = min((DWORD)data.size(), (DWORD)sizeof(res.enumValue.data));
                    memcpy(res.enumValue.data, data.data(), res.enumValue.dataLen);
                }
                break;
            }
            case REG_OP_QUERYINFOKEY: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] QueryInfo\t%s\n", virReg.GetPath(req.hKey).c_str());
                wstring className;
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
                WriteLog(LOADER_LOG_ALL, L"[Reg] DeleteKey\t%s\n", virReg.GetPath(req.hKey).c_str());
                res.ret = virReg.DeleteKey(req.hKey, req.deleteKey.path);
                break;
            }
            case REG_OP_DELETEVALUE: {
                WriteLog(LOADER_LOG_ALL, L"[Reg] DeleteValue\t%s\n", virReg.GetPath(req.hKey).c_str());
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
            WriteLog(LOADER_LOG_ERROR, L"[Loader] Client %u Write Pipe error: %d\n", pid, GetLastError());
            break;
        }

    }
    return 0;
}

// 命名管道服务端线程
DWORD WINAPI PipeServerThread(LPVOID lpParam) {
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
            WriteLog(LOADER_LOG_ERROR, L"[PipeServer] CreateNamedPipeW failed: %d\n", GetLastError());
            CloseHandle(hPipe);
            continue;
        }

        if(!ConnectNamedPipe(hPipe, NULL) && GetLastError()!=ERROR_PIPE_CONNECTED)
        {
            WriteLog(LOADER_LOG_ERROR, L"[PipeServer] Named pipe connect failed: %d\n", GetLastError());
            break;
        }

        DWORD clientPid = 0;
        GetNamedPipeClientProcessId(hPipe, &clientPid);
        WriteLog(LOADER_LOG_INFO, L"[PipeServer] Client connected (PID=%u)\n", clientPid);

        HANDLE hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)hPipe, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);    // 不等待线程，独立运行
        } else {
            WriteLog(LOADER_LOG_ERROR, L"[PipeServer] CreateThread failed: %d\n", GetLastError());
            CloseHandle(hPipe);
        }
    }
    return 0;
}

// 注入 DLL 到目标进程
BOOL InjectDll(HANDLE hProcess, const wchar_t* dllPath) {
    // 注入dll
   const wchar_t* ret = _RemoteCall(hProcess, L"kernel32.dll", "LoadLibraryW", dllPath);
   if(ret != _CALL_SUCCESS){
        WriteLog(LOADER_LOG_ERROR, ret, GetLastError());
        return FALSE;
   }
   ret = _RemoteCall(hProcess, L"HookDLL.dll", "SetPipeName", g_pipeName);
   WriteLog(LOADER_LOG_ALL, L"[Loader] SetPipeName on subprocess");
   if(ret != _CALL_SUCCESS){
        WriteLog(LOADER_LOG_ERROR, ret, GetLastError());
        return FALSE;
   }
    return TRUE;
}

// 主函数
int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "chs");
    int argi = 1;
    while (true) {
        if (argi >= argc) {
            _putws(L"Usage: loader.exe [--debug|-D] [--error|-E] [--silent|-S] [--regfile|-RF <file>] <command> [args...]");
            return 1;
        }
        // 日志输出
        if (wcscmp(argv[argi], L"--debug")==0 ||
            wcscmp(argv[argi], L"-D")==0
        ) Config.logLevel = LOADER_LOG_ALL;
        else if (wcscmp(argv[argi], L"--error")==0 ||
            wcscmp(argv[argi], L"-E")==0
        ) Config.logLevel = LOADER_LOG_ERROR;
        else if (wcscmp(argv[argi], L"--silent")==0 ||
            wcscmp(argv[argi], L"-S")==0
        ) Config.logLevel = LOADER_LOG_SILENT;
        // 虚拟注册表文件存储
        else if (wcscmp(argv[argi], L"--regfile")==0 ||
            wcscmp(argv[argi], L"-RF")==0
        ) {
            if (++argi >= argc) {
                _putws(L"Usage: loader.exe [--debug|-D] [--error|-E] [--silent|-S] <command> [args...]");
                return 1;
            }
            Config.regFilePath = argv[argi];
        }
        else break;
        ++argi;
    }

    // 设置管道名
    swprintf(g_pipeName, L"\\\\.\\pipe\\VirtualRegistryPipe%d",GetCurrentProcessId());
    InitializeCriticalSection(&g_LogCs);
    // 启动命名管道服务端
    CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    if(!virReg.LoadBinary(Config.regFilePath)){
        WriteLog(LOADER_LOG_ALL, L"[Loader] RegFile load failed %d\n", GetLastError());
    }

    // 构建命令行
    wstringstream cmdLineBuilder;
    wstring cmdLine;
    for (; argi < argc; argi++) {
        if (wcschr(argv[argi], L' '))
            cmdLineBuilder << L'\"' << argv[argi] <<  L'\"';
        else
            cmdLineBuilder << argv[argi];
        if (argi < argc-1) cmdLineBuilder << L' ';
    }
    cmdLine = cmdLineBuilder.str();

    WriteLog(LOADER_LOG_ALL, L"[Loader] CmdLine: [%ls]\n", cmdLine.c_str());
    // 创建子进程（挂起）
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL,
            (LPWSTR)cmdLine.c_str(),
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi))
    {
        WriteLog(LOADER_LOG_ERROR, L"[Loader] CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    WriteLog(LOADER_LOG_INFO, L"[Loader] Process created (PID: %d). Injecting DLL...\n", pi.dwProcessId);

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
        WriteLog(LOADER_LOG_ERROR, L"[Loader] Injection failed, terminating process.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    WriteLog(LOADER_LOG_INFO, L"[Loader] DLL injected, resuming thread.\n");
    ResumeThread(pi.hThread);

    // 等待子进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    WriteLog(LOADER_LOG_INFO, L"[Loader] Process exited with code %d\n", exitCode);


    if (!virReg.SaveBinary(Config.regFilePath))
        WriteLog(LOADER_LOG_ERROR, L"[Loader] RegFile save failed: %d\n", GetLastError());
    if (Config.logLevel==LOADER_LOG_ALL) {
        WriteLog(LOADER_LOG_ALL, L"REG:\n%s", virReg.ToString().c_str());
        _putws(L"Input anything ...");
        getchar();
    }

    // 清理资源
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteCriticalSection(&g_LogCs);
    return 0;
}