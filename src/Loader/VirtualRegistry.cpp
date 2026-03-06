#include "VirtualRegistry.h"

#include <functional>

#include "Common.hpp"

using namespace std;

// 预定义根键 ID (与 winreg.h 中的常量一致)

// 二进制文件魔数和版本
const DWORD VREG_MAGIC = 0x47455256;  // "VREG" 小端：V(0x56) R(0x52) E(0x45) G(0x47)
const DWORD VREG_VERSION = 1;

VirtualRegistry::VirtualRegistry() : nextId_(0x1000ul) {
    InitializeCriticalSection(&cs_);

    // 初始化五个根节点
    auto createRoot = [this](HKEY id, const wchar_t* name) {
        auto node = make_unique<Node>();
        node->id = id;
        node->name = name;
        node->parentId = 0;
        nodes_[id] = move(node);
    };

    createRoot(HKEY_CLASSES_ROOT, L"HKEY_CLASSES_ROOT");
    createRoot(HKEY_CURRENT_USER, L"HKEY_CURRENT_USER");
    createRoot(HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE");
    createRoot(HKEY_USERS, L"HKEY_USERS");
    createRoot(HKEY_CURRENT_CONFIG, L"HKEY_CURRENT_CONFIG");
}

VirtualRegistry::~VirtualRegistry() {
    DeleteCriticalSection(&cs_);
}

// 内部辅助（无锁，调用者需持有临界区）
VirtualRegistry::Node* VirtualRegistry::GetNode(HKEY id) {
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? it->second.get() : nullptr;
}

const VirtualRegistry::Node* VirtualRegistry::GetNode(HKEY id) const {
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? it->second.get() : nullptr;
}

HKEY VirtualRegistry::AllocateId() {
    return (HKEY)InterlockedIncrement(&nextId_);
}

// ------------------- 单级内部操作（无锁） -------------------

LONG VirtualRegistry::CreateKeyInternal(HKEY parentId, const wstring& name, HKEY& newId, DWORD& disposition) {
    Node* parent = GetNode(parentId);
    if (!parent) return ERROR_INVALID_HANDLE;

    auto it = parent->subkeys.find(name);
    if (it != parent->subkeys.end()) {
        newId = it->second;
        disposition = REG_OPENED_EXISTING_KEY;
        return ERROR_SUCCESS;
    }

    HKEY id = AllocateId();
    auto node = make_unique<Node>();
    node->id = id;
    node->name = name;
    node->parentId = parentId;

    parent->subkeys[name] = id;
    nodes_[id] = move(node);

    newId = id;
    disposition = REG_CREATED_NEW_KEY;
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::OpenKeyInternal(HKEY parentId, const wstring& name, HKEY& outId) {
    Node* parent = GetNode(parentId);
    if (!parent) return ERROR_INVALID_HANDLE;

    auto it = parent->subkeys.find(name);
    if (it == parent->subkeys.end()) return ERROR_PATH_NOT_FOUND;

    outId = it->second;
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::DeleteKeyInternal(HKEY parentId, const wstring& name) {
    Node* parent = GetNode(parentId);
    if (!parent) return ERROR_INVALID_HANDLE;

    auto it = parent->subkeys.find(name);
    if (it == parent->subkeys.end()) return ERROR_PATH_NOT_FOUND;

    HKEY childId = it->second;
    Node* child = GetNode(childId);
    if (!child) {
        parent->subkeys.erase(it);
        return ERROR_SUCCESS;
    }
    // TOREAD

    // 递归收集所有后代节点ID
    vector<HKEY> toDelete;
    function<void(HKEY)> collect = [&](HKEY id) {
        Node* n = GetNode(id);
        if (!n) return;
        toDelete.push_back(id);
        for (const auto& pair : n->subkeys) {
            collect(pair.second);
        }
    };
    collect(childId);

    // 从父节点的子键映射中移除
    parent->subkeys.erase(it);

    // 从 nodes_ 中删除所有收集的节点
    for (HKEY id : toDelete) {
        nodes_.erase(id);
    }

    return ERROR_SUCCESS;
}

// ------------------- 多级路径递归辅助（无锁） -------------------

LONG VirtualRegistry::CreateKeyPath(HKEY parentId, const wstring& path, HKEY& newId, DWORD& disposition) {
    size_t pos = path.find(L'\\');
    if (pos == wstring::npos) {
        return CreateKeyInternal(parentId, path, newId, disposition);
    }

    wstring first = path.substr(0, pos);
    wstring rest = path.substr(pos + 1);

    HKEY interId;
    DWORD interDisp;
    LONG ret = CreateKeyInternal(parentId, first, interId, interDisp);
    if (ret != ERROR_SUCCESS) return ret;

    return CreateKeyPath(interId, rest, newId, disposition);
}

LONG VirtualRegistry::OpenKeyPath(HKEY parentId, const wstring& path, HKEY& outId) {
    size_t pos = path.find(L'\\');
    if (pos == wstring::npos) {
        return OpenKeyInternal(parentId, path, outId);
    }

    wstring first = path.substr(0, pos);
    wstring rest = path.substr(pos + 1);

    HKEY interId;
    LONG ret = OpenKeyInternal(parentId, first, interId);
    if (ret != ERROR_SUCCESS) return ret;

    return OpenKeyPath(interId, rest, outId);
}

LONG VirtualRegistry::DeleteKeyPath(HKEY parentId, const wstring& path) {
    size_t pos = path.find_last_of(L'\\');
    if (pos == wstring::npos) {
        return DeleteKeyInternal(parentId, path);
    }

    wstring parentPath = path.substr(0, pos);
    wstring last = path.substr(pos + 1);

    HKEY parentNodeId;
    LONG ret = OpenKeyPath(parentId, parentPath, parentNodeId);
    if (ret != ERROR_SUCCESS) return ret;

    return DeleteKeyInternal(parentNodeId, last);
}

// ------------------- 公有 API（加锁） -------------------

LONG VirtualRegistry::CreateKey(HKEY parentId, const wstring& path, HKEY& newId, DWORD& disposition) {
    wstring normPath = path;
    // 去除尾部反斜杠
    while (!normPath.empty() && normPath.back() == L'\\')
        normPath.pop_back();
    // 去除前导反斜杠
    while (!normPath.empty() && normPath.front() == L'\\')
        normPath.erase(0, 1);
    // 空路径不能创建键
    if (normPath.empty())
        return ERROR_INVALID_PARAMETER;

    EnterCriticalSection(&cs_);
    LONG ret = CreateKeyPath(parentId, normPath, newId, disposition);
    LeaveCriticalSection(&cs_);
    return ret;
}

LONG VirtualRegistry::OpenKey(HKEY parentId, const wstring& path, HKEY& outId) {
    wstring normPath = path;
    // 去除尾部反斜杠
    while (!normPath.empty() && normPath.back() == L'\\')
        normPath.pop_back();
    // 去除前导反斜杠（相对路径不应有，但容错处理）
    while (!normPath.empty() && normPath.front() == L'\\')
        normPath.erase(0, 1);
    // 空路径表示打开父键本身
    if (normPath.empty()) {
        outId = parentId;
        return ERROR_SUCCESS;
    }
    EnterCriticalSection(&cs_);
    LONG ret = OpenKeyPath(parentId, normPath, outId);
    LeaveCriticalSection(&cs_);
    return ret;
}

LONG VirtualRegistry::CloseKey(HKEY id) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(id);
    LeaveCriticalSection(&cs_);
    return node ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
}

LONG VirtualRegistry::QueryValue(HKEY keyId, const wstring& valueName, DWORD& type, vector<BYTE>& data) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }
    auto it = node->values.find(valueName);
    if (it == node->values.end()) {
        LeaveCriticalSection(&cs_);
        return ERROR_FILE_NOT_FOUND;
    }
    type = it->second.type;
    data = it->second.data;
    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::SetValue(HKEY keyId, const wstring& valueName, DWORD type, const vector<BYTE>& data) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }
    Value v;
    v.type = type;
    v.data = data;
    node->values[valueName] = move(v);
    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::DeleteValue(HKEY keyId, const wstring& valueName) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }
    auto it = node->values.find(valueName);
    if (it == node->values.end()) {
        LeaveCriticalSection(&cs_);
        return ERROR_FILE_NOT_FOUND;
    }
    node->values.erase(it);
    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::DeleteKey(HKEY parentId, const wstring& path) {
    EnterCriticalSection(&cs_);
    LONG ret = DeleteKeyPath(parentId, path);
    LeaveCriticalSection(&cs_);
    return ret;
}

LONG VirtualRegistry::EnumKey(HKEY keyId, DWORD index, wstring& name) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }
    if (index >= node->subkeys.size()) {
        LeaveCriticalSection(&cs_);
        return ERROR_NO_MORE_ITEMS;
    }
    auto it = node->subkeys.begin();
    advance(it, index);
    name = it->first;
    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::EnumValue(HKEY keyId, DWORD index, wstring& valueName, DWORD& type, vector<BYTE>& data) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }
    if (index >= node->values.size()) {
        LeaveCriticalSection(&cs_);
        return ERROR_NO_MORE_ITEMS;
    }
    auto it = node->values.begin();
    advance(it, index);
    valueName = it->first;
    type = it->second.type;
    data = it->second.data;
    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

LONG VirtualRegistry::QueryInfoKey(
    HKEY keyId, DWORD &subKeys, DWORD &maxSubKeyLen
    , DWORD &maxClassLen, DWORD &values, DWORD &maxValueNameLen
    , DWORD &maxValueLen, DWORD &securityDescriptor
    , FILETIME &lastWriteTime, wstring &className
) {
    EnterCriticalSection(&cs_);
    Node* node = GetNode(keyId);
    if (!node) {
        LeaveCriticalSection(&cs_);
        return ERROR_INVALID_HANDLE;
    }

    // 子键信息
    subKeys = (DWORD)node->subkeys.size();
    maxSubKeyLen = 0;
    for (const auto& pair : node->subkeys) {
        DWORD len = (DWORD)pair.first.length();   // 字符数，不含终止 null
        if (len > maxSubKeyLen) maxSubKeyLen = len;
    }

    // 值信息
    values = (DWORD)node->values.size();
    maxValueNameLen = 0;
    maxValueLen = 0;
    for (const auto& pair : node->values) {
        DWORD nameLen = (DWORD)pair.first.length();
        if (nameLen > maxValueNameLen) maxValueNameLen = nameLen;
        DWORD dataLen = (DWORD)pair.second.data.size();
        if (dataLen > maxValueLen) maxValueLen = dataLen;
    }

    // 类名（未使用）
    className.clear();
    maxClassLen = 0;

    // 安全描述符和最后写入时间不实现
    securityDescriptor = 0;
    lastWriteTime.dwLowDateTime = 0;
    lastWriteTime.dwHighDateTime = 0;

    LeaveCriticalSection(&cs_);
    return ERROR_SUCCESS;
}

// ------------------- 二进制序列化（保持不变） -------------------

bool VirtualRegistry::SaveBinary(const wstring& filePath) {
    /***
     * VREG
     * 版本号
     * 节点数
     * ... 节点数据
     */
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool success = true;
    EnterCriticalSection(&cs_);

    DWORD magic = VREG_MAGIC;
    DWORD version = VREG_VERSION;
    DWORD nodeCount = static_cast<DWORD>(nodes_.size());

    do{
        if (!WriteFileSafe(hFile, &magic, sizeof(magic)) ||
            !WriteFileSafe(hFile, &version, sizeof(version)) ||
            !WriteFileSafe(hFile, &nodeCount, sizeof(nodeCount))
        ){
            success = false;
            break;
        }
        
        for (const auto& pair : nodes_)
            if (!WriteNode(hFile, pair.second.get())){
                success = false;
                break;
            }
        
    } while (false);
    
    LeaveCriticalSection(&cs_);
    CloseHandle(hFile);
    return success;
}

bool VirtualRegistry::WriteNode(HANDLE hFile, const Node* node) {
    /***
     * 节点ID
     * 父节点ID(0为根节点)
     * 键名长度(字符数)
     * [ 键名(wchar_t) ]
     * 值数量
     *   值名长度(字符数)
     *   [ 值名(wchar_t) ]
     *   值类型
     *   数据长度(字节)
     *   [ 数据(字节) ]
     */
    DWORD written;
    if (!WriteFileSafe(hFile, &node->id, sizeof(node->id)) ||
        !WriteFileSafe(hFile, &node->parentId, sizeof(node->parentId))
    ) return false;

    DWORD nameLen = static_cast<DWORD>(node->name.size());
    if (!WriteFileSafe(hFile, &nameLen, sizeof(nameLen))) return false;
    if (nameLen > 0)
        if (!WriteFileSafe(hFile, node->name.c_str(), nameLen * sizeof(wchar_t)))
            return false;

    DWORD valueCount = static_cast<DWORD>(node->values.size());
    if (!WriteFileSafe(hFile, &valueCount, sizeof(valueCount))) return false;

    for (const auto& valPair : node->values) {
        const wstring& valName = valPair.first;
        const Value& val = valPair.second;

        DWORD valNameLen = static_cast<DWORD>(valName.size());
        if (!WriteFileSafe(hFile, &valNameLen, sizeof(valNameLen))) return false;
        if (valNameLen > 0)
            if (!WriteFileSafe(hFile, valName.c_str(), valNameLen * sizeof(wchar_t)))
                return false;

        if (!WriteFileSafe(hFile, &val.type, sizeof(val.type))) return false;

        DWORD dataLen = static_cast<DWORD>(val.data.size());
        if (!WriteFileSafe(hFile, &dataLen, sizeof(dataLen))) return false;
        if (dataLen > 0)
            if (!WriteFileSafe(hFile, val.data.data(), dataLen))
                return false;
    }
    return true;
}

bool VirtualRegistry::LoadBinary(const wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool success = true;
    DWORD magic, version, nodeCount;
    HKEY maxId = 0;

    EnterCriticalSection(&cs_);

    do {
        if (!ReadFileSafe(hFile, &magic, sizeof(magic)) ||
            magic != VREG_MAGIC ||
            !ReadFileSafe(hFile, &version, sizeof(version)) ||
            version != VREG_VERSION ||
            !ReadFileSafe(hFile, &nodeCount, sizeof(nodeCount))
        ){
            success = false;
            break;
        }

        unordered_map<HKEY, unique_ptr<Node>> tempNodes;
        DWORD hasRoot=0;

        for (DWORD i = 0; i < nodeCount; ++i) {
            Node node;
            if (!ReadNode(hFile, node)) {
                success = false;
                break;
            }

            if(node.id==HKEY_CLASSES_ROOT)      hasRoot|=0x01;
            else if(node.id==HKEY_CURRENT_USER) hasRoot|=0x02;
            else if(node.id==HKEY_LOCAL_MACHINE) hasRoot|=0x04;
            else if(node.id==HKEY_USERS)        hasRoot|=0x08;
            else if(node.id==HKEY_CURRENT_CONFIG) hasRoot|=0x10;
            else if(node.id>maxId) maxId=node.id;
            
            auto ptr = make_unique<Node>(move(node));
            tempNodes[ptr->id] = move(ptr);
        }

        // 确保根节点存在
        if (hasRoot!=0x1F) {
            success = false;
            break;
        }
        
        // 重建父子关系
        for (const auto& pair : tempNodes) {
            Node* node = pair.second.get();
            if (node->parentId != 0) {
                auto parentIt = tempNodes.find(node->parentId);
                if (parentIt != tempNodes.end()) {
                    parentIt->second->subkeys[node->name] = node->id;
                }else{
                    success = false;
                    break;
                }
            }
        }

        if (success) {
            nodes_.clear();
            nodes_ = move(tempNodes);
            nextId_ = (ULONG64)maxId + 1;
        }

    } while (false);
    
    LeaveCriticalSection(&cs_);
    CloseHandle(hFile);
    return success;
}

bool VirtualRegistry::ReadNode(HANDLE hFile, Node& node) {
    if (!ReadFileSafe(hFile, &node.id, sizeof(node.id)) ||
        !ReadFileSafe(hFile, &node.parentId, sizeof(node.parentId))
    ) return false;

    DWORD nameLen;
    if (!ReadFileSafe(hFile, &nameLen, sizeof(nameLen))) return false;
    if (nameLen > 0) {
        vector<wchar_t> buf(nameLen);
        if (!ReadFileSafe(hFile, buf.data(), nameLen * sizeof(wchar_t))) return false;
        node.name.assign(buf.data(), nameLen);
    } else {
        node.name.clear();
    }

    DWORD valueCount;
    if (!ReadFileSafe(hFile, &valueCount, sizeof(valueCount))) return false;

    for (DWORD i = 0; i < valueCount; ++i) {
        DWORD valNameLen;
        if (!ReadFileSafe(hFile, &valNameLen, sizeof(valNameLen))) return false;

        wstring valName;
        if (valNameLen > 0) {
            vector<wchar_t> buf(valNameLen);
            if (!ReadFileSafe(hFile, buf.data(), valNameLen * sizeof(wchar_t))) return false;
            valName.assign(buf.data(), valNameLen);
        }

        Value val;
        if (!ReadFileSafe(hFile, &val.type, sizeof(val.type))) return false;

        DWORD dataLen;
        if (!ReadFileSafe(hFile, &dataLen, sizeof(dataLen))) return false;
        if (dataLen > 0) {
            val.data.resize(dataLen);
            if (!ReadFileSafe(hFile, val.data.data(), dataLen)) return false;
        }

        node.values[valName] = move(val);
    }

    node.subkeys.clear(); // 将在加载完所有节点后重建
    return true;
}

wstring VirtualRegistry::_str(Node *node, int level){
    wstring finalStr;
    if(!node) finalStr;
    for(int i=0 ; i<level ; ++i) finalStr+=L"  ";
    finalStr+=L"[" + node->name + L"]\n";
    for(const auto& pair: node->subkeys){
        finalStr+=_str(GetNode(pair.second), level+1);
    }
    return finalStr;
}

wstring VirtualRegistry::ToString(){
    return _str(GetNode(HKEY_CLASSES_ROOT), 0) + 
        _str(GetNode(HKEY_CURRENT_USER), 0) + 
        _str(GetNode(HKEY_LOCAL_MACHINE), 0) + 
        _str(GetNode(HKEY_USERS), 0) + 
        _str(GetNode(HKEY_CURRENT_CONFIG), 0);
}

wstring VirtualRegistry::GetPath(HKEY hKey){
    wstring path;
    Node* n = GetNode(hKey);
    while(n){
        if(n->parentId==0){
            return n->name + path;
        }
        path = L'\\'+n->name + path;
        n = GetNode(n->parentId);
    }
    return path;
}
