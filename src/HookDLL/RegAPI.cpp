#include "HookDLL/RegAPI.hpp"

#include "HookDLL/HookDLL.hpp"

template <typename T>
const T& min(const T& a, const T&b){
    return b < a ? b : a;
}

// RegCreateKeyExW
LONG WINAPI HookRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    // TODO 未实现samDesired, lpSecurityAttributes的存储
    if (Reserved != 0)
        return ERROR_INVALID_PARAMETER;
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
    // TODO 未实现ulOptions的传参
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
    // TODO  未将lpcbData进行传参
    if (lpReserved != NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpData != NULL && lpcbData == NULL)
        return ERROR_INVALID_PARAMETER;
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.queryValue.valueName, lpValueName);

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;
    if (res.ret != ERROR_SUCCESS && res.ret != ERROR_MORE_DATA)
        return res.ret;

    const DWORD& dataLen = res.queryValue.dataLen;   // 实际数据大小（字节）
    if (lpType) *lpType = res.queryValue.type;
    if (lpData == NULL)      // 仅查询缓冲区大小
    {
        if (lpcbData != NULL)
            *lpcbData = dataLen;
        return ERROR_SUCCESS;
    }

    if (*lpcbData < dataLen || res.ret == ERROR_MORE_DATA)
    {
        *lpcbData = dataLen;        // 告诉用户实际需要的大小
        return ERROR_MORE_DATA;     // 缓冲区不足
    }
    else // ret == ERROR_SUCCESS
    {
        // 服务端返回了完整数据，复制到用户缓冲区
        memcpy(lpData, res.queryValue.data, dataLen);
        *lpcbData = dataLen;
        return ERROR_SUCCESS;
    }
}

// RegSetValueExW
LONG WINAPI HookRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    if (Reserved != 0)
        return ERROR_INVALID_PARAMETER;
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_SETVALUE;
    req.hKey = hKey;
    if (lpValueName) wcscpy_s(req.setValue.valueName, lpValueName);
    req.setValue.type = dwType;
    req.setValue.dataLen = min(cbData, (DWORD)REGFORM_DATA_LEN);
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

// RegDeleteKeyExW
LONG WINAPI HookRegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
    // TODO samDesired的处理
    if (lpSubKey==NULL || *lpSubKey==0 || Reserved!=0)
        return ERROR_INVALID_PARAMETER;
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_DELETEKEY;
    req.hKey = hKey;
    wcscpy_s(req.deleteKey.path, lpSubKey);

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
    // TODO 未实现lpftLastWriteTime
    if (lpReserved != NULL)
        return ERROR_INVALID_PARAMETER;
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
    if (lpReserved != NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpValueName != NULL && lpcValueName == NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpData != NULL && lpcbData == NULL)
        return ERROR_INVALID_PARAMETER;
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_ENUMVALUE;
    req.hKey = hKey;
    req.enumInfo.index = dwIndex;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret != ERROR_SUCCESS)
        return res.ret;

    DWORD nameLen = wcsnlen(res.enumValue.valueName, REGFORM_MAX_NAME)
        , dataLen = (DWORD)res.enumValue.dataLen;
    if (lpValueName && *lpcValueName<nameLen+1) {
        *lpcValueName = nameLen+1;
        return ERROR_MORE_DATA;
    }
    if (lpData && *lpcbData<dataLen) {
        *lpcbData = dataLen;
        return ERROR_MORE_DATA;
    }
    
    if (lpcValueName) {
        *lpcValueName = nameLen;
        if (lpValueName) {
            wcsncpy(lpValueName, res.enumValue.valueName, nameLen);
            lpValueName[nameLen] = L'\0';
        }
    }
    if (lpType) *lpType = res.enumValue.type;
    if (lpcbData) {
        *lpcbData = dataLen;
        if (lpData)
            memcpy(lpData, res.enumValue.data, dataLen);
    }
    return res.ret;
}

// RegQueryInfoKeyW
LONG WINAPI HookRegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, FILETIME* lpftLastWriteTime)
{
    // TODO lpClass未存储
    if (lpReserved != NULL)
        return ERROR_INVALID_PARAMETER;
    if (lpClass != NULL && lpcClass == NULL)
        return ERROR_INVALID_PARAMETER;
    RegRequest req;
    RegResponse res;
    req.op = REG_OP_QUERYINFOKEY;
    req.hKey = hKey;

    if (!SendRequestAndReceive(req, res))
        return ERROR_INTERNAL_ERROR;

    if (res.ret != ERROR_SUCCESS)
        return res.ret;

    DWORD classNameLen = wcsnlen(res.queryInfo.className, REGFORM_MAX_NAME);
    if (lpClass && *lpcClass<classNameLen+1) {
        *lpcClass = classNameLen;
        return ERROR_MORE_DATA;
    }
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
    if (lpcClass) {
        *lpcClass = classNameLen;
        if (lpClass) {
            wcsncpy(lpClass, res.queryInfo.className, classNameLen);
            lpClass[classNameLen] = L'\0';
        }
    }
    return ERROR_SUCCESS;
}
