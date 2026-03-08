#ifndef LOADER_CONFIG
#define LOADER_CONFIG

#include <string>

enum LoaderLogLevel {
    LOADER_LOG_SILENT=0 ,
    LOADER_LOG_ERROR=10 ,
    LOADER_LOG_INFO=20 ,
    LOADER_LOG_ALL=30 ,
};
static struct {
    std::wstring regFilePath = L"reg.dat";
    LoaderLogLevel logLevel = LOADER_LOG_INFO;
} Config;

#endif //LOADER_CONFIG