#ifndef VIRTUALREGISTRY_H
#define VIRTUALREGISTRY_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <functional>

class VirtualRegistry {
public:
    VirtualRegistry();
    ~VirtualRegistry();

    // 二进制持久化
    bool LoadBinary(const std::wstring& filePath);
    bool SaveBinary(const std::wstring& filePath);

    // 注册表操作（支持多级路径）
    LONG CreateKey(HKEY parentId, const std::wstring& path, HKEY& newId, DWORD& disposition);
    LONG OpenKey(HKEY parentId, const std::wstring& path, HKEY& outId);
    LONG CloseKey(HKEY id);
    LONG QueryValue(HKEY keyId, const std::wstring& valueName, DWORD& type, std::vector<BYTE>& data);
    LONG SetValue(HKEY keyId, const std::wstring& valueName, DWORD type, const std::vector<BYTE>& data);
    LONG DeleteValue(HKEY keyId, const std::wstring& valueName);
    LONG DeleteKey(HKEY parentId, const std::wstring& path);
    LONG EnumKey(HKEY keyId, DWORD index, std::wstring& name);
    LONG EnumValue(HKEY keyId, DWORD index, std::wstring& valueName, DWORD& type, std::vector<BYTE>& data);
    LONG QueryInfoKey(HKEY keyId,
        DWORD& subKeys,
        DWORD& maxSubKeyLen,
        DWORD& maxClassLen,
        DWORD& values,
        DWORD& maxValueNameLen,
        DWORD& maxValueLen,
        DWORD& securityDescriptor,
        FILETIME& lastWriteTime,
        std::wstring& className);
    std::wstring ToString();
    std::wstring GetPath(HKEY hKey);

private:
    struct Value {
        DWORD type;
        std::vector<BYTE> data;
    };

    struct Node {
        HKEY id;
        std::wstring name;
        HKEY parentId;                 // 0 表示根节点（无父节点）
        std::map<std::wstring, HKEY> subkeys;   // 子键名称 -> 子节点ID
        std::map<std::wstring, Value> values;     // 值名称 -> 值数据
    };

    std::unordered_map<HKEY, std::unique_ptr<Node>> nodes_;
    ULONG64 nextId_;                      // 下一个可用的节点ID（从 0x1000 开始）
    CRITICAL_SECTION cs_;                // 保护内部数据结构

    // 内部辅助函数（无锁，调用者需持有临界区）
    Node* GetNode(HKEY id);
    const Node* GetNode(HKEY id) const;
    HKEY AllocateId();

    // 单级内部操作（无锁）
    LONG CreateKeyInternal(HKEY parentId, const std::wstring& name, HKEY& newId, DWORD& disposition);
    LONG OpenKeyInternal(HKEY parentId, const std::wstring& name, HKEY& outId);
    LONG DeleteKeyInternal(HKEY parentId, const std::wstring& name);

    // 多级路径递归辅助（无锁）
    LONG CreateKeyPath(HKEY parentId, const std::wstring& path, HKEY& newId, DWORD& disposition);
    LONG OpenKeyPath(HKEY parentId, const std::wstring& path, HKEY& outId);
    LONG DeleteKeyPath(HKEY parentId, const std::wstring& path);

    // 二进制序列化辅助
    bool WriteNode(HANDLE hFile, const Node* node);
    bool ReadNode(HANDLE hFile, Node& node);

    std::wstring _str(Node* node, int level);
};

#endif // VIRTUALREGISTRY_H