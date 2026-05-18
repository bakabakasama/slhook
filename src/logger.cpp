#include "logger.h"
#include <cstdio>
#include <cstdarg>
#include <windows.h>
#include <string>
#include <map>
#include <mutex>

// Thread-safe map to cache module names so we don't spam the Windows API
std::map<HMODULE, std::string> g_ModuleNames;
std::mutex g_LogMutex;

// Helper function to figure out who called the logger
std::string GetCallerPluginName(void* callerAddress) {
    HMODULE hModule = NULL;
    
    // Ask Windows which module (DLL) owns the memory address that called us
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)callerAddress,
        &hModule)) {
        return "Unknown";
    }

    // Lock the cache map
    std::lock_guard<std::mutex> lock(g_LogMutex);

    // If we've seen this module before, return its cached name
    auto it = g_ModuleNames.find(hModule);
    if (it != g_ModuleNames.end()) {
        return it->second;
    }

    // First time seeing this module, ask Windows for its file path
    char pathBuf[MAX_PATH];
    if (GetModuleFileNameA(hModule, pathBuf, MAX_PATH)) {
        std::string fullPath(pathBuf);
        
        // Strip everything except the filename
        size_t lastSlash = fullPath.find_last_of("\\/");
        std::string fileName = (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;
        
        // Cache it and return
        g_ModuleNames[hModule] = fileName;
        return fileName;
    }

    return "Unknown";
}

// Our internal loader logger (tags itself as [Loader])
void Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    FILE* file = fopen("pso2h.log", "a"); // Unifying to pso2h.log
    if (file) {
        fprintf(file, "[Loader] %s\n", message.c_str());
        fflush(file);
        fclose(file);
    }
}

// The exported logger used by the plugins
extern "C" __declspec(dllexport) void pso2hLogLine(const char* format, ...) {
    // 1. Grab the exact memory address that called this function
    void* callerAddress = __builtin_return_address(0);
    
    // 2. Resolve that address to a DLL name
    std::string pluginName = GetCallerPluginName(callerAddress);

    // 3. Format the string
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    // 4. Thread-safe write to the unified log
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    FILE* file = fopen("pso2h.log", "a");
    if (file) {
        fprintf(file, "[%s] %s\n", pluginName.c_str(), buffer);
        fflush(file);
        fclose(file);
    }
}