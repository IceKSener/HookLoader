#ifndef COMMON_HPP
#define COMMON_HPP

#include <windows.h>

static const wchar_t* _call_msg[] = {
    L"VirtualAllocEx failed: %d\n",
    L"WriteProcessMemory failed: %d\n",
    L"GetProcAddress failed: %d\n",
    L"CreateRemoteThread failed: %d\n"
};
#define _CALL_SUCCESS NULL
#define _CALL_ALLOC _call_msg[0]
#define _CALL_MEMWRITE _call_msg[1]
#define _CALL_GETADDR _call_msg[2]
#define _CALL_THREAD _call_msg[3]

static const wchar_t* _RemoteCall(HANDLE process, const wchar_t* module, const char* funcName, const wchar_t* strArg){
    SIZE_T size = (wcslen(strArg) + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(process, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        return _CALL_ALLOC;
    }
    DWORD ret;
    if (!WriteProcessMemory(process, pRemoteBuf, strArg, size, NULL))
    {
        VirtualFreeEx(process, pRemoteBuf, 0, MEM_RELEASE);
        return _CALL_MEMWRITE;
    }
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(module), funcName);
    if (!pLoadLibrary)
    {
        VirtualFreeEx(process, pRemoteBuf, 0, MEM_RELEASE);
        return _CALL_GETADDR;
    }
    HANDLE hRemoteThread = CreateRemoteThread(process, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hRemoteThread)
    {
        VirtualFreeEx(process, pRemoteBuf, 0, MEM_RELEASE);
        return _CALL_THREAD;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    VirtualFreeEx(process, pRemoteBuf, 0, MEM_RELEASE);
    return _CALL_SUCCESS;
}
static BOOL WriteFileSafe(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite){
    DWORD cbWritten;
    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &cbWritten, NULL) && cbWritten == nNumberOfBytesToWrite;
}
static BOOL ReadFileSafe(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead){
    DWORD cbRead;
    return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &cbRead, NULL) && cbRead == nNumberOfBytesToRead;
}

#endif // COMMON_HPP