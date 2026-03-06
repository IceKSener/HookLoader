#include "HookDLL/RegAPI.hpp"

#include "HookDLL/HookDLL.hpp"

// RegCreateKeyExW
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_CREATEKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.createKey.path, lpSubKey);
    req.createKey.dwOptions = dwOptions;
    req.createKey.samDesired = samDesired;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (phkResult) *phkResult = res.hKey;
    if (lpdwDisposition) *lpdwDisposition = res.createKey.disposition;

    return res.ret;
}

// RegOpenKeyExW
LONG WINAPI HookRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_OPENKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.openKey.path, lpSubKey);
    req.openKey.samDesired = samDesired;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (phkResult) *phkResult = res.hKey;

    return res.ret;
}

// RegQueryValueExW
LONG WINAPI HookRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.queryValue.valueName, lpValueName);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (lpType) *lpType = res.queryValue.type;
    if (lpData && lpcbData) {
        DWORD copyLen = (*lpcbData<res.queryValue.dataLen)? *lpcbData: res.queryValue.dataLen;
        memcpy(lpData, res.queryValue.data, copyLen);
        *lpcbData = copyLen;
    } else if (lpcbData) {
        *lpcbData = res.queryValue.dataLen;
    }

    return res.ret;
}

// RegSetValueExW
LONG WINAPI HookRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_SETVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.setValue.valueName, lpValueName);
    req.setValue.type = dwType;
    req.setValue.dataLen = (cbData<(DWORD)sizeof(req.setValue.data))? cbData: (DWORD)sizeof(req.setValue.data);
    memcpy(req.setValue.data, lpData, req.setValue.dataLen);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;
        
    return res.ret;
}

// RegCloseKey
LONG WINAPI HookRegCloseKey(HKEY hKey)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_CLOSEKEY;
    req.hKey = hKey;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;
    
    return res.ret;
}

// RegDeleteKeyW
LONG WINAPI HookRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_DELETEKEY;
    req.hKey = hKey;
    if (lpSubKey) wcscpy_s(req.deleteKey.path, lpSubKey);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    return res.ret;
}

// RegDeleteValueW
LONG WINAPI HookRegDeleteValueW(HKEY hKey, LPCWSTR lpValueName)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_DELETEVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.deleteValue.valueName, lpValueName);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    return res.ret;
}

// RegEnumKeyExW
LONG WINAPI HookRegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_ENUMKEY;
    req.hKey = hKey;
    req.enumInfo.index = dwIndex;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret == ERROR_SUCCESS && lpName && lpcName) {
        wcsncpy(lpName, res.enumKey.name, *lpcName - 1);
        lpName[*lpcName - 1] = L'\0';
        *lpcName = (DWORD)wcslen(lpName) + 1;
    }

    return res.ret;
}

// RegEnumValueW
LONG WINAPI HookRegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_ENUMVALUE;
    req.hKey = hKey;
    req.enumInfo.index = dwIndex;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret == ERROR_SUCCESS) {
        if (lpValueName && lpcValueName) {
            wcsncpy(lpValueName, res.enumValue.valueName, *lpcValueName - 1);
            lpValueName[*lpcValueName - 1] = L'\0';
            *lpcValueName = (DWORD)wcslen(lpValueName) + 1;
        }
        if (lpType) *lpType = res.enumValue.type;
        if (lpData && lpcbData) {
            DWORD copyLen = (*lpcbData<res.enumValue.dataLen)? *lpcbData: res.enumValue.dataLen;
            memcpy(lpData, res.enumValue.data, copyLen);
            *lpcbData = copyLen;
        }
    }
    return res.ret;
}

// RegQueryInfoKeyW
LONG WINAPI HookRegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, FILETIME* lpftLastWriteTime)
{
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYINFOKEY;
    req.hKey = hKey;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret != ERROR_SUCCESS)
        return res.ret;

    // 填充各输出参数（如果指针非空）
    if (lpcSubKeys) *lpcSubKeys = res.queryInfo.subKeys;
    if (lpcMaxSubKeyLen) *lpcMaxSubKeyLen = res.queryInfo.maxSubKeyLen;
    if (lpcMaxClassLen) *lpcMaxClassLen = res.queryInfo.maxClassLen;
    if (lpcValues) *lpcValues = res.queryInfo.values;
    if (lpcMaxValueNameLen) *lpcMaxValueNameLen = res.queryInfo.maxValueNameLen;
    if (lpcMaxValueLen) *lpcMaxValueLen = res.queryInfo.maxValueLen;
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = res.queryInfo.securityDescriptor;
    if (lpftLastWriteTime) *lpftLastWriteTime = res.queryInfo.lastWriteTime;

    // 处理类名
    if (lpClass && lpcClass) {
        // 计算实际需要的字符数（包括 null 终止符）
        size_t required = wcslen(res.queryInfo.className) + 1;
        DWORD bufferSize = *lpcClass;   // 输入时缓冲区的容量（字符数）

        if (bufferSize > 0) {
            wcsncpy(lpClass, res.queryInfo.className, bufferSize - 1);
            lpClass[bufferSize - 1] = L'\0';
        }
        *lpcClass = (DWORD)required;
    }
    else if (lpcClass) {
        // lpClass 为 NULL，仅返回所需大小
        *lpcClass = (DWORD)wcslen(res.queryInfo.className) + 1;
    }

    return ERROR_SUCCESS;
}
