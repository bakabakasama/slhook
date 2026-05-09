#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include "api.h"
#include "logger.h"
#include "network.h" // Gives us access to g_SendHandlers, g_NetworkMutex, etc.

extern "C" {
    // ---------------------------------------------------------
    // Safe Cross-Boundary Memory Management
    // ---------------------------------------------------------
    __declspec(dllexport) void* pso2hAlloc(size_t size) {
        // HEAP_ZERO_MEMORY automatically zeroes out the allocation (like calloc)
        // which prevents garbage data from crashing string parsers.
        return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    }

    __declspec(dllexport) void pso2hFree(void* ptr) {
        if (ptr) {
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }

    // ---------------------------------------------------------
    // Ignored / Stubs (Required so plugins don't crash on load)
    // ---------------------------------------------------------
    __declspec(dllexport) void pso2hGGCRCBypass() {}
    __declspec(dllexport) void pso2hExecuteFunction() {}
    __declspec(dllexport) int isGGReady() { return 1; }
    __declspec(dllexport) int pso2hGetVersion() { return 1000; }
    __declspec(dllexport) int pso2hCheckVersion() { return 1; }


    __declspec(dllexport) void __cdecl pso2hDoLua(const char* script) {
    if (script) {
        // We'll log exactly what TelepipeProxy is trying to inject into the game
         char buf[1024];
        snprintf(buf, sizeof(buf), "[API-LUA-INTERCEPT] Telepipe sent script:\n%s", script);
         Log(buf);
      } else {
            Log("[API-LUA-INTERCEPT] Telepipe sent a NULL script.");
      }
    }

    // ---------------------------------------------------------
    // Network Registration API
    // ---------------------------------------------------------
    __declspec(dllexport) int pso2hRegisterHandlerSend(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName) {
        uint16_t packetId = (mainId << 8) + subId;
        std::string name = handlerName ? handlerName : "Unknown";
        
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerSend: %s [0x%04X]", name.c_str(), packetId);
        Log(buf);

        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        PacketHandler handler = {callback, name};
        g_SendHandlers[packetId].push_back(handler);
        
        return 1; // Return True/Success
    }

    __declspec(dllexport) int pso2hRegisterHandlerRecv(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName) {
        uint16_t packetId = (mainId << 8) + subId;
        std::string name = handlerName ? handlerName : "Unknown";
        
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerRecv: %s [0x%04X]", name.c_str(), packetId);
        Log(buf);

        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        PacketHandler handler = {callback, name};
        g_RecvHandlers[packetId].push_back(handler);
        
        return 1;
    }

    __declspec(dllexport) int pso2hRegisterHandlerSendAll(void* callback, const char* handlerName) {
        std::string name = handlerName ? handlerName : "Unknown";
        
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerSendAll: %s", name.c_str());
        Log(buf);

        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        PacketHandler handler = {callback, name};
        g_SendAllHandlers.push_back(handler);
        
        return 1;
    }

    __declspec(dllexport) int pso2hRegisterHandlerRecvAll(void* callback, const char* handlerName) {
        std::string name = handlerName ? handlerName : "Unknown";
        
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerRecvAll: %s", name.c_str());
        Log(buf);

        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        PacketHandler handler = {callback, name};
        g_RecvAllHandlers.push_back(handler);
        
        return 1;
    }
}