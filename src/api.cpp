#include "api.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include "logger.h"
#include "network.h"

// Note that we wrap these in extern C as to not mangle the export names
extern "C"
{
    // ---------------------------------------------------------
    // Unimplemented stubs
    // ---------------------------------------------------------
    __declspec(dllexport) void pso2hGGCRCBypass() {}
    __declspec(dllexport) void pso2hExecuteFunction() {}
    __declspec(dllexport) int isGGReady() { return 1; }
    __declspec(dllexport) int pso2hGetVersion() { return 1000; }
    __declspec(dllexport) int pso2hCheckVersion() { return 1; }

    // ---------------------------------------------------------
    // Lua Engine stub
    // ---------------------------------------------------------
    // This one probably needs some explaining. DoLua was originally
    // used by TelepipeProxy specifically to intercept the networking
    // within the engine, which was a good solution when GameGuard
    // was a problem. Since GameGuard is gone, we don't actually need
    // this one anymore and just use MinHook to redirect the engine.
    __declspec(dllexport) void __cdecl pso2hDoLua(const char* script)
    {
    // if (script) {
    //      char buf[1024];
    //     snprintf(buf, sizeof(buf), "[API-LUA-INTERCEPT] Telepipe sent script:\n%s", script);
    //      Log(buf);
    //   } else {
    //         Log("[API-LUA-INTERCEPT] Telepipe sent a NULL script.");
    //   }
    }

    // ---------------------------------------------------------
    // Memory management reimplementations
    // ---------------------------------------------------------
    __declspec(dllexport) void* pso2hAlloc(size_t size)
    {
        return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    }

    __declspec(dllexport) void pso2hFree(void* ptr)
    {
        if (ptr) {
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }

    // ---------------------------------------------------------
    // Networking - Send/Recv Callbacks
    // ---------------------------------------------------------
    __declspec(dllexport) int pso2hRegisterHandlerSend(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName)
    {
        // Build packet by bitshifting mainId and putting subId in it's place.
        uint16_t packetId = (mainId << 8) + subId;

        // Store handler name for logging
        std::string name = handlerName ? handlerName : "Unknown";
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerSend: %s [0x%04X]", name.c_str(), packetId);
        Log(buf);

        // Create a recursive mutex to only lock a thread, not the whole game
        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        // Register the callbacks
        PacketHandler handler = {callback, name};
        g_SendHandlers[packetId].push_back(handler);
        
        // Return 1 on success (you'll know if it fails by now lol)
        return 1;
    }

    // Same function as above, ad hominen
    __declspec(dllexport) int pso2hRegisterHandlerRecv(void* callback, uint8_t mainId, uint8_t subId, const char* handlerName)
    {
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


    // ---------------------------------------------------------
    // Networking - SendAll/RecvAll Callbacks
    // ---------------------------------------------------------
    __declspec(dllexport) int pso2hRegisterHandlerSendAll(void* callback, const char* handlerName)
    {
        // Note, we don't actually care about the packet here because it all goes to the same place.
        // Store handler name for logging
        std::string name = handlerName ? handlerName : "Unknown";
        char buf[256];
        snprintf(buf, sizeof(buf), "[API] RegisterHandlerSendAll: %s", name.c_str());
        Log(buf);

        // Create a recursive mutex to only lock a thread, not the whole game
        std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
        // Register the callbacks
        PacketHandler handler = {callback, name};
        g_SendAllHandlers.push_back(handler);
        
        return 1;
    }

    // You know the deal by now
    __declspec(dllexport) int pso2hRegisterHandlerRecvAll(void* callback, const char* handlerName)
    {
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