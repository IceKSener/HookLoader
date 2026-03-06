#include "Common.hpp"

const wchar_t *_RemoteCall(HANDLE process, const wchar_t *module, const char *funcName, const wchar_t *strArg) {
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

BOOL WriteFileSafe(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite) {
    DWORD cbWritten;
    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &cbWritten, NULL) && cbWritten == nNumberOfBytesToWrite;
}

BOOL ReadFileSafe(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead) {
    DWORD cbRead;
    return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &cbRead, NULL) && cbRead == nNumberOfBytesToRead;
}
