#include <windows.h>
#include <stdio.h>

// 注入 DLL 到目标进程（已挂起状态）
BOOL InjectDll(HANDLE hProcess, const wchar_t* dllPath)
{
    SIZE_T size = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        wprintf(L"VirtualAllocEx failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath, size, NULL))
    {
        wprintf(L"WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary)
    {
        wprintf(L"GetProcAddress failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hRemoteThread)
    {
        wprintf(L"CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        wprintf(L"Usage: loader.exe <command> [args...]\n");
        return 1;
    }

    // 构建命令行字符串
    wchar_t cmdLine[32768] = {0};
    for (int i = 1; i < argc; i++)
    {
        if (i > 1) wcscat_s(cmdLine, L" ");
        // 如果参数包含空格，需加引号（简单处理，假设参数本身不含引号）
        if (wcschr(argv[i], L' '))
        {
            wcscat_s(cmdLine, L"\"");
            wcscat_s(cmdLine, argv[i]);
            wcscat_s(cmdLine, L"\"");
        }
        else
        {
            wcscat_s(cmdLine, argv[i]);
        }
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // 创建挂起进程
    if (!CreateProcessW(NULL,
                        cmdLine,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_SUSPENDED,  // 挂起以便注入
                        NULL,
                        NULL,
                        &si,
                        &pi))
    {
        wprintf(L"CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    wprintf(L"Process created (PID: %d). Injecting DLL...\n", pi.dwProcessId);

    // 获取当前 DLL 的完整路径（假设 HookDLL.dll 与 loader.exe 在同一目录）
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    wchar_t* pSlash = wcsrchr(dllPath, L'\\');
    if (pSlash)
        *(pSlash + 1) = L'\0';
    wcscat_s(dllPath, L"HookDLL.dll");

    if (!InjectDll(pi.hProcess, dllPath))
    {
        wprintf(L"Injection failed, terminating process.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    wprintf(L"Injection successful, resuming thread.\n");
    ResumeThread(pi.hThread);

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    wprintf(L"Process exited with code %d\n", exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}