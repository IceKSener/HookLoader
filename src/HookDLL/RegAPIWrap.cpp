#include "HookDLL/RegAPIWrap.hpp"

#include <string>
#include <vector>

#include "HookDLL/RegAPI.hpp"
#include "RegForm.hpp"

using namespace std;

// 辅助函数：将 ANSI 字符串转换为宽字符串
static wstring AnsiToWide(LPCSTR ansiStr) {
    if (!ansiStr) return wstring();
    int len = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, nullptr, 0);
    wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, &wstr[0], len);
    wstr.pop_back(); // 移除末尾多余的 null
    return wstr;
}

// 辅助函数：将宽字符串转换为 ANSI
static string WideToAnsi(LPCWSTR wideStr) {
    if (!wideStr) return string();
    int len = WideCharToMultiByte(CP_ACP, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    string str(len, '\0');
    WideCharToMultiByte(CP_ACP, 0, wideStr, -1, &str[0], len, nullptr, nullptr);
    str.pop_back();
    return str;
}


// ================== Ex 系列 ANSI API 钩子 ==================

LONG WINAPI HookRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    wstring wClass = lpClass ? AnsiToWide(lpClass) : wstring();
    return HookRegCreateKeyExW(hKey, wSubKey.c_str(), Reserved, (LPWSTR)wClass.c_str(), dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LONG WINAPI HookRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    return HookRegOpenKeyExW(hKey, wSubKey.c_str(), ulOptions, samDesired, phkResult);
}

LONG WINAPI HookRegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    wstring wValueName = AnsiToWide(lpValueName);
    DWORD type = 0;
    DWORD dataLenW = 0;
    LONG ret = HookRegQueryValueExW(hKey, wValueName.c_str(), lpReserved, &type, nullptr, &dataLenW);
    if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) return ret;
    if (lpType) *lpType = type;

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        vector<wchar_t> wData(dataLenW / sizeof(wchar_t) + 1);
        DWORD dataLenWActual = dataLenW;
        ret = HookRegQueryValueExW(hKey, wValueName.c_str(), lpReserved, &type, (LPBYTE)wData.data(), &dataLenWActual);
        if (ret != ERROR_SUCCESS) return ret;

        string ansiData = WideToAnsi(wData.data());
        DWORD ansiDataLen = (DWORD)ansiData.size() + 1;
        if (lpData && lpcbData) {
            DWORD copyLen = min(*lpcbData, ansiDataLen);
            memcpy(lpData, ansiData.c_str(), copyLen);
            *lpcbData = copyLen;
            if (copyLen < ansiDataLen) return ERROR_MORE_DATA;
        } else if (lpcbData) {
            *lpcbData = ansiDataLen;
        }
        return ERROR_SUCCESS;
    } else {
        return HookRegQueryValueExW(hKey, wValueName.c_str(), lpReserved, lpType, lpData, lpcbData);
    }
}

LONG WINAPI HookRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    wstring wValueName = AnsiToWide(lpValueName);
    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ) {
        int wLen = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpData, cbData, nullptr, 0);
        vector<wchar_t> wData(wLen);
        MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpData, cbData, wData.data(), wLen);
        return HookRegSetValueExW(hKey, wValueName.c_str(), Reserved, dwType, (const BYTE*)wData.data(), wLen * sizeof(wchar_t));
    } else {
        return HookRegSetValueExW(hKey, wValueName.c_str(), Reserved, dwType, lpData, cbData);
    }
}

LONG WINAPI HookRegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime) {
    wchar_t wName[REGFORM_MAX_NAME], wClass[REGFORM_MAX_NAME];
    DWORD wNameLen = REGFORM_MAX_NAME, wClassLen = REGFORM_MAX_NAME;
    LONG ret = HookRegEnumKeyExW(hKey, dwIndex, wName, &wNameLen, lpReserved, wClass, &wClassLen, lpftLastWriteTime);
    if (ret != ERROR_SUCCESS) return ret;

    if (lpName && lpcName) {
        string ansiName = WideToAnsi(wName);
        DWORD ansiNameLen = (DWORD)ansiName.size() + 1;
        if (*lpcName < ansiNameLen) {
            *lpcName = ansiNameLen;
            return ERROR_MORE_DATA;
        }
        memcpy(lpName, ansiName.c_str(), ansiNameLen);
        *lpcName = ansiNameLen;
    }
    if (lpClass && lpcClass) {
        string ansiClass = WideToAnsi(wClass);
        DWORD ansiClassLen = (DWORD)ansiClass.size() + 1;
        if (*lpcClass < ansiClassLen) {
            *lpcClass = ansiClassLen;
            return ERROR_MORE_DATA;
        }
        memcpy(lpClass, ansiClass.c_str(), ansiClassLen);
        *lpcClass = ansiClassLen;
    }
    return ERROR_SUCCESS;
}

// ================== 旧版 Unicode API 钩子 ==================

LONG WINAPI HookRegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    return HookRegCreateKeyExW(hKey, lpSubKey, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, phkResult, nullptr);
}

LONG WINAPI HookRegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    return HookRegOpenKeyExW(hKey, lpSubKey, 0, KEY_ALL_ACCESS, phkResult);
}

LONG WINAPI HookRegQueryValueW(HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue) {
    DWORD type = REG_SZ;
    DWORD dataLen = *lpcbValue;
    LONG ret = HookRegQueryValueExW(hKey, L"", nullptr, &type, (LPBYTE)lpValue, &dataLen);
    if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA) {
        *lpcbValue = dataLen;
    }
    return ret;
}

LONG WINAPI HookRegSetValueW(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) {
    return HookRegSetValueExW(hKey, L"", 0, dwType, (const BYTE*)lpData, cbData);
}

LONG WINAPI HookRegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName) {
    DWORD cchNameActual = cchName;
    return HookRegEnumKeyExW(hKey, dwIndex, lpName, &cchNameActual, nullptr, nullptr, nullptr, nullptr);
}

// ================== 旧版 ANSI API 钩子 ==================

LONG WINAPI HookRegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    return HookRegCreateKeyExW(hKey, wSubKey.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, phkResult, nullptr);
}

LONG WINAPI HookRegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    return HookRegOpenKeyExW(hKey, wSubKey.c_str(), 0, KEY_ALL_ACCESS, phkResult);
}
// TOREAD
LONG WINAPI HookRegQueryValueA(HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    DWORD type = REG_SZ;
    DWORD dataLenW = *lpcbValue;
    vector<wchar_t> wBuffer(dataLenW / sizeof(wchar_t) + 1);
    LONG ret = HookRegQueryValueExW(hKey, L"", nullptr, &type, (LPBYTE)wBuffer.data(), &dataLenW);
    if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA) {
        if (ret == ERROR_SUCCESS && lpValue) {
            string ansiStr = WideToAnsi(wBuffer.data());
            DWORD ansiBytes = (DWORD)ansiStr.size() + 1;
            if (ansiBytes <= *lpcbValue) {
                memcpy(lpValue, ansiStr.c_str(), ansiBytes);
                *lpcbValue = ansiBytes;
            } else {
                *lpcbValue = ansiBytes;
                ret = ERROR_MORE_DATA;
            }
        } else {
            *lpcbValue = dataLenW; // 粗略估计
        }
    }
    return ret;
}

LONG WINAPI HookRegSetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    int wLen = MultiByteToWideChar(CP_ACP, 0, lpData, cbData, nullptr, 0);
    vector<wchar_t> wData(wLen);
    MultiByteToWideChar(CP_ACP, 0, lpData, cbData, wData.data(), wLen);
    return HookRegSetValueExW(hKey, wSubKey.c_str(), 0, dwType, (const BYTE*)wData.data(), wLen * sizeof(wchar_t));
}

LONG WINAPI HookRegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    return HookRegDeleteKeyW(hKey, wSubKey.c_str());
}

LONG WINAPI HookRegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    wstring wValueName = AnsiToWide(lpValueName);
    return HookRegDeleteValueW(hKey, wValueName.c_str());
}

LONG WINAPI HookRegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName) {
    wchar_t wName[256];
    DWORD cchWName = 256;
    LONG ret = HookRegEnumKeyExW(hKey, dwIndex, wName, &cchWName, nullptr, nullptr, nullptr, nullptr);
    if (ret == ERROR_SUCCESS) {
        string ansiName = WideToAnsi(wName);
        DWORD ansiChars = (DWORD)ansiName.size() + 1;
        if (ansiChars <= cchName) {
            memcpy(lpName, ansiName.c_str(), ansiChars);
        } else {
            return ERROR_MORE_DATA;
        }
    }
    return ret;
}

LONG WINAPI HookRegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    wchar_t wValueName[256];
    DWORD wValueNameLen = 256;
    DWORD type;
    DWORD dataLenW = 0;
    LONG ret = HookRegEnumValueW(hKey, dwIndex, wValueName, &wValueNameLen, lpReserved, &type, nullptr, &dataLenW);
    if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) return ret;
    if (lpType) *lpType = type;

    vector<BYTE> wData;
    if (lpData && lpcbData) {
        wData.resize(dataLenW);
        DWORD dataLenWActual = dataLenW;
        ret = HookRegEnumValueW(hKey, dwIndex, wValueName, &wValueNameLen, lpReserved, &type, wData.data(), &dataLenWActual);
        if (ret != ERROR_SUCCESS) return ret;
    }

    if (lpValueName && lpcValueName) {
        string ansiValueName = WideToAnsi(wValueName);
        DWORD ansiNameLen = (DWORD)ansiValueName.size() + 1;
        if (*lpcValueName < ansiNameLen) {
            *lpcValueName = ansiNameLen;
            return ERROR_MORE_DATA;
        }
        memcpy(lpValueName, ansiValueName.c_str(), ansiNameLen);
        *lpcValueName = ansiNameLen;
    }

    if (lpData && lpcbData) {
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
            string ansiData = WideToAnsi((LPCWSTR)wData.data());
            DWORD ansiDataLen = (DWORD)ansiData.size() + 1;
            if (*lpcbData < ansiDataLen) {
                *lpcbData = ansiDataLen;
                return ERROR_MORE_DATA;
            }
            memcpy(lpData, ansiData.c_str(), ansiDataLen);
            *lpcbData = ansiDataLen;
        } else {
            DWORD copyLen = min(*lpcbData, (DWORD)wData.size());
            memcpy(lpData, wData.data(), copyLen);
            *lpcbData = copyLen;
            if (copyLen < wData.size()) return ERROR_MORE_DATA;
        }
    } else if (lpcbData) {
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
            *lpcbData = dataLenW; // 粗略估计
        } else {
            *lpcbData = dataLenW;
        }
    }
    return ERROR_SUCCESS;
}

LONG WINAPI HookRegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime) {
    wchar_t wClass[256];
    DWORD wClassLen = 256;
    LONG ret = HookRegQueryInfoKeyW(hKey, wClass, &wClassLen, lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    if (ret != ERROR_SUCCESS) return ret;

    if (lpClass && lpcClass) {
        string ansiClass = WideToAnsi(wClass);
        DWORD ansiClassLen = (DWORD)ansiClass.size() + 1;
        if (*lpcClass < ansiClassLen) {
            *lpcClass = ansiClassLen;
            return ERROR_MORE_DATA;
        }
        memcpy(lpClass, ansiClass.c_str(), ansiClassLen);
        *lpcClass = ansiClassLen;
    } else if (lpcClass) {
        string ansiClass = WideToAnsi(wClass);
        *lpcClass = (DWORD)ansiClass.size() + 1;
    }
    return ERROR_SUCCESS;
}
