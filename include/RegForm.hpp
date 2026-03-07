#ifndef REGFORM_HPP
#define REGFORM_HPP

#include <windows.h>

// 注册表操作协议定义

#define REGFORM_MAX_PATH 512
#define REGFORM_MAX_NAME 256
#define REGFORM_DATA_LEN 4096

enum RegOperation {
    REG_OP_CREATEKEY,
    REG_OP_OPENKEY,
    REG_OP_QUERYVALUE,
    REG_OP_SETVALUE,
    REG_OP_CLOSEKEY,
    REG_OP_ENUMKEY,
    REG_OP_ENUMVALUE,
    REG_OP_QUERYINFOKEY,
    REG_OP_DELETEKEY,
    REG_OP_DELETEVALUE,
};

struct RegRequest {
    RegOperation op;           // 操作码
    HKEY hKey;                  // 主键句柄（几乎所有操作需要）

    union {
        // REG_OP_CREATEKEY
        struct {
            wchar_t path[REGFORM_MAX_PATH];   // 子键路径
            DWORD dwOptions;      // 创建选项
            DWORD samDesired;     // 访问权限
        } createKey;

        // REG_OP_OPENKEY
        struct {
            wchar_t path[REGFORM_MAX_PATH];
            DWORD samDesired;
        } openKey;

        // REG_OP_QUERYVALUE
        struct {
            wchar_t valueName[REGFORM_MAX_NAME];
        } queryValue;

        // REG_OP_SETVALUE
        struct {
            wchar_t valueName[REGFORM_MAX_NAME];
            DWORD type;
            DWORD dataLen;        // 数据长度（字节）
            BYTE data[REGFORM_DATA_LEN];       // 值数据
        } setValue;

        // REG_OP_ENUMKEY / REG_OP_ENUMVALUE
        struct {
            DWORD index;           // 枚举索引
        } enumInfo;

        // REG_OP_DELETEKEY
        struct {
            wchar_t path[REGFORM_MAX_PATH];
        } deleteKey;

        // REG_OP_DELETEVALUE
        struct {
            wchar_t valueName[REGFORM_MAX_NAME];
        } deleteValue;

        // REG_OP_QUERYINFOKEY 无需额外参数
        // REG_OP_CLOSEKEY 无需额外参数
    };

    RegRequest(){ ZeroMemory(this, sizeof(RegRequest)); }
};

struct RegResponse {
    LONG ret;                   // 返回码（ERROR_SUCCESS 等）
    HKEY hKey;                  // 可能返回新句柄（如 CREATEKEY/OPENKEY）

    union {
        // REG_OP_CREATEKEY
        struct {
            DWORD disposition;    // REG_CREATED_NEW_KEY 或 REG_OPENED_EXISTING_KEY
        } createKey;

        // REG_OP_QUERYVALUE
        struct {
            DWORD type;
            DWORD dataLen;
            BYTE data[4096];
        } queryValue;

        // REG_OP_ENUMKEY
        struct {
            wchar_t name[REGFORM_MAX_NAME];     // 子键名称
        } enumKey;

        // REG_OP_ENUMVALUE
        struct {
            wchar_t valueName[REGFORM_MAX_NAME];
            DWORD type;
            DWORD dataLen;
            BYTE data[REGFORM_DATA_LEN];
        } enumValue;

        // REG_OP_QUERYINFOKEY
        struct {
            DWORD subKeys;
            DWORD maxSubKeyLen;
            DWORD maxClassLen;
            DWORD values;
            DWORD maxValueNameLen;
            DWORD maxValueLen;
            DWORD securityDescriptor;
            FILETIME lastWriteTime;
            wchar_t className[REGFORM_MAX_NAME];
        } queryInfo;

        // 其他操作无需额外数据，可留空或仅占位
    };

    RegResponse(){ ZeroMemory(this, sizeof(RegResponse)); }
};

#endif // REGFORM_HPP