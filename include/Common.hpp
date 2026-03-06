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

const wchar_t* _RemoteCall(HANDLE process, const wchar_t* module, const char* funcName, const wchar_t* strArg);
BOOL WriteFileSafe(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite);
BOOL ReadFileSafe(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead);

#endif // COMMON_HPP