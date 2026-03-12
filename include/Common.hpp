#ifndef COMMON_HPP
#define COMMON_HPP

#include <windows.h>
#include <string>

static const wchar_t* _call_msg[] = {
    L"VirtualAllocEx failed: %s\n",
    L"WriteProcessMemory failed: %s\n",
    L"GetProcAddress failed: %s\n",
    L"CreateRemoteThread failed: %s\n"
};
#define _CALL_SUCCESS NULL
#define _CALL_ALLOC _call_msg[0]
#define _CALL_MEMWRITE _call_msg[1]
#define _CALL_GETADDR _call_msg[2]
#define _CALL_THREAD _call_msg[3]

const wchar_t* _RemoteCall(HANDLE process, const wchar_t* module, const char* funcName, const wchar_t* strArg, DWORD* exitCode=nullptr);
BOOL WriteFileSafe(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite);
BOOL ReadFileSafe(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead);
// 辅助函数：将 ANSI 字符串转换为宽字符串
std::wstring AnsiToWide(LPCSTR ansiStr);
// 辅助函数：将宽字符串转换为 ANSI
std::string WideToAnsi(LPCWSTR wideStr);
std::wstring GetErrorMessage(DWORD errorCode);
std::wstring GetLastErrorMessage();
#define LASTERRMSG GetLastErrorMessage().c_str()

#endif // COMMON_HPP