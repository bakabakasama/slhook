#pragma once
#include <cstdint>

// ---------------------------------------------------------
// pso2h Public Plugin SDK Interface
// ---------------------------------------------------------
extern "C" {
    // Memory Management
    __declspec(dllexport) void* pso2hAlloc(size_t size);
    __declspec(dllexport) void pso2hFree(void* ptr);

    // Engine & Anti-Cheat Stubs (Required for plugin compatibility)
    __declspec(dllexport) void pso2hGGCRCBypass();
    __declspec(dllexport) void pso2hExecuteFunction();
    __declspec(dllexport) int isGGReady();
    __declspec(dllexport) int pso2hGetVersion();
    __declspec(dllexport) int pso2hCheckVersion();

    // Scripting
    __declspec(dllexport) void __cdecl pso2hDoLua(const char* script);

    // Network Registration APIs
    __declspec(dllexport) int pso2hRegisterHandlerSend(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName);
    __declspec(dllexport) int pso2hRegisterHandlerRecv(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName);
    
    __declspec(dllexport) int pso2hRegisterHandlerSendAll(void* callback, const char* handlerName);
    __declspec(dllexport) int pso2hRegisterHandlerRecvAll(void* callback, const char* handlerName);
}