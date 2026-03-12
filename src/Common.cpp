#include "Common.hpp"

#include <sstream>

using namespace std;

const wchar_t *_RemoteCall(HANDLE process, const wchar_t *module, const char *funcName, const wchar_t *strArg, DWORD *exitCode) {
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

    if (exitCode) GetExitCodeThread(hRemoteThread, exitCode);
    
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

wstring AnsiToWide(LPCSTR ansiStr) {
    if (!ansiStr) return wstring();
    int len = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, nullptr, 0);
    wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, &wstr[0], len);
    wstr.pop_back(); // 移除末尾多余的 null
    return wstr;
}

string WideToAnsi(LPCWSTR wideStr) {
    if (!wideStr) return string();
    int len = WideCharToMultiByte(CP_ACP, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    string str(len, '\0');
    WideCharToMultiByte(CP_ACP, 0, wideStr, -1, &str[0], len, nullptr, nullptr);
    str.pop_back();
    return str;
}

// 将指定的错误码转换为字符串描述
wstring GetErrorMessage(DWORD errorCode) {
    wchar_t *messageBuffer = nullptr;
    wstring message;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS;

    // 调用 FormatMessage 获取系统错误描述
    size_t size = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 默认语言
        (LPWSTR)&messageBuffer,
        0,
        nullptr
    );
    if (size == 0) {
        // 如果获取失败，返回包含错误码的备用信息
        message = L"Unknown error code";
    } else {
        // 将缓冲区内容复制到 wstring
        message.assign(messageBuffer, size);
        // 去除末尾的换行符（\r\n）
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
            message.pop_back();
        }
        // 释放 FormatMessage 分配的缓冲区
        LocalFree(messageBuffer);
    }

    wstringstream strBuilder;
    strBuilder << L'(' << errorCode << L')' << message;
    return strBuilder.str();
}

// 获取最近一次错误的字符串描述
wstring GetLastErrorMessage() {
    return GetErrorMessage(GetLastError());
}