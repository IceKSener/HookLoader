#include "HookDLL/RegAPIWrap.hpp"

#include <string>
#include <vector>

#include "HookDLL/RegAPI.hpp"
#include "RegForm.hpp"
#include "Common.hpp"

using namespace std;

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
    if (lpData != NULL && lpcbData == NULL)
        return ERROR_INVALID_PARAMETER;
    wstring wValueName = AnsiToWide(lpValueName);
    DWORD type = 0;
    DWORD dataLen = 0;
    LONG ret = HookRegQueryValueExW(hKey, wValueName.c_str(), lpReserved, &type, nullptr, &dataLen);
    if (ret != ERROR_SUCCESS) return ret;

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        vector<wchar_t> wData(dataLen / sizeof(wchar_t) + 1);
        ret = HookRegQueryValueExW(hKey, wValueName.c_str(), lpReserved, lpType, (LPBYTE)wData.data(), &dataLen);
        if (ret != ERROR_SUCCESS) return ret;

        string ansiData = WideToAnsi(wData.data());
        dataLen = (DWORD)ansiData.size() + 1;
        if (lpData && lpcbData) {
            DWORD copyLen = min(*lpcbData, dataLen);
            memcpy(lpData, ansiData.c_str(), copyLen);
            *lpcbData = copyLen;
            if (copyLen < dataLen) return ERROR_MORE_DATA;
        } else if (lpcbData) {
            *lpcbData = dataLen;
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

LONG WINAPI HookRegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    wstring wSubKey = AnsiToWide(lpSubKey);
    return HookRegDeleteKeyExW(hKey, wSubKey.c_str(), samDesired, Reserved);
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
    return HookRegOpenKeyExW(hKey, lpSubKey, 0, KEY_READ, phkResult);
}

LONG WINAPI HookRegQueryValueW(HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpValue, PLONG lpcbValue) {
    if (lpSubKey != NULL && *lpSubKey != L'\0') {
        LONG ret = HookRegOpenKeyExW(hKey, lpSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) return ret;
    }
    return HookRegQueryValueExW(hKey, nullptr , nullptr, nullptr, (LPBYTE)lpValue, (LPDWORD)lpcbValue);
}

LONG WINAPI HookRegSetValueW(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) {
    if (dwType == REG_SZ || lpData==NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpSubKey != NULL && *lpSubKey != L'\0') {
        LONG ret = HookRegOpenKeyExW(hKey, lpSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) return ret;
    }
    cbData = (DWORD)(wcslen(lpData) + 1) * sizeof(WCHAR);
    return HookRegSetValueExW(hKey, nullptr, 0, dwType, (const BYTE*)lpData, cbData);
}

LONG WINAPI HookRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    return HookRegDeleteKeyExW(hKey, lpSubKey, KEY_WOW64_64KEY, 0);
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
    return HookRegOpenKeyExA(hKey, lpSubKey, 0, KEY_READ, phkResult);
}

LONG WINAPI HookRegQueryValueA(HKEY hKey, LPCSTR lpSubKey, LPSTR lpValue, PLONG lpcbValue) {
    if (lpSubKey != NULL && *lpSubKey != L'\0') {
        LONG ret = HookRegOpenKeyExA(hKey, lpSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) return ret;
    }
    return HookRegQueryValueExA(hKey, nullptr , nullptr, nullptr, (LPBYTE)lpValue, (LPDWORD)lpcbValue);
}

LONG WINAPI HookRegSetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData) {
    if (dwType == REG_SZ || lpData==NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpSubKey != NULL && *lpSubKey != L'\0') {
        LONG ret = HookRegOpenKeyExA(hKey, lpSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) return ret;
    }
    cbData = (DWORD)(strlen(lpData) + 1);
    return HookRegSetValueExA(hKey, nullptr, 0, dwType, (const BYTE*)lpData, cbData);
}

LONG WINAPI HookRegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    return HookRegDeleteKeyExA(hKey, lpSubKey, KEY_WOW64_64KEY, 0);
}

LONG WINAPI HookRegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    wstring wValueName = AnsiToWide(lpValueName);
    return HookRegDeleteValueW(hKey, wValueName.c_str());
}

LONG WINAPI HookRegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName) {
    wchar_t wName[REGFORM_MAX_NAME];
    DWORD cchWName = REGFORM_MAX_NAME;
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
    if (lpValueName != NULL && lpcValueName == NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpData != NULL && lpcbData == NULL)
        return ERROR_INVALID_PARAMETER;
    wchar_t wValueName[REGFORM_MAX_NAME+1];
    DWORD wValueNameLen = REGFORM_MAX_NAME+1;
    LONG ret = HookRegEnumValueW(hKey, dwIndex, wValueName, &wValueNameLen, lpReserved, nullptr, nullptr, nullptr);
    if (ret != ERROR_SUCCESS) return ret;
    string valueName = WideToAnsi(wValueName);
    DWORD nameLen = valueName.length();
    if (lpValueName && *lpcValueName<nameLen+1) {
        *lpcValueName = nameLen+1;
        return ERROR_MORE_DATA;
    }

    ret = HookRegEnumValueW(hKey, dwIndex, nullptr, nullptr, lpReserved, lpType, lpData, lpcbData);
    if (ret != ERROR_SUCCESS) return ret;

    if (lpcValueName) {
        *lpcValueName = nameLen;
        if (lpValueName)
            strcpy(lpValueName, valueName.data());
    }
    return ERROR_SUCCESS;
}

LONG WINAPI HookRegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime) {
    if (lpClass != NULL && lpcClass == NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpClass || lpcClass) {
        wchar_t wClass[REGFORM_MAX_NAME+1];
        DWORD wClassLen = REGFORM_MAX_NAME+1;
        LONG ret = HookRegQueryInfoKeyW(hKey, wClass, &wClassLen, lpReserved, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (ret != ERROR_SUCCESS)
            return ret;
        string className = WideToAnsi(wClass);
        DWORD classLen = className.length();
        if (lpClass && *lpcClass<classLen+1) {
            *lpcClass = classLen;
            return ERROR_MORE_DATA;
        }
        HookRegQueryInfoKeyW(hKey, nullptr, nullptr, lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
        *lpcClass = classLen;
        if (lpClass)
            strcpy(lpClass, className.c_str());
        return ERROR_SUCCESS;
    } else {
        return HookRegQueryInfoKeyW(hKey, nullptr, nullptr, lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    }
}
