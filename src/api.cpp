#include "api.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include "logger.h"
#include "network.h"
#include "lua.h"
#include "scanner.h"
#include <thread>

// Certain plugins absolutely REQUIRE PSO2Hook::Packet(). We can only get so far away...
namespace PSO2Hook
{
#pragma pack(push, 1)
    struct PacketHeader
    {
        uint32_t size;
        uint8_t type;
        uint8_t subtype;
        uint8_t flags;
        uint8_t padding;
    };

#pragma pack(pop)

    // Export it
    class Packet
    {
    public:
        Packet(PacketHeader *h);
        Packet(uint8_t **packet); // Double pointers, lame
        void* *ref;
        PacketHeader *header;
        uint16_t pktID;
        uint32_t dataSize;
        uint8_t *data;
        ~Packet();
    };

    Packet::Packet(PacketHeader *h)
    {
        ref = nullptr;
        header = h;
        pktID = (h->subtype << 8) | h->type;
        dataSize = h->size - 8;
        data = (uint8_t*)h + 8;
    }

    Packet::Packet(uint8_t **packet)
    {
        ref = (void**)packet; // Another one
        uint8_t* rawBuffer = *packet;
        header = (PacketHeader*)rawBuffer;
        pktID = (header->subtype << 8) | header->type;
        dataSize = header->size - 8;
        data = rawBuffer + 8;
    }

    Packet::~Packet()
    {
        // The proxy handles the actual memory cleanup, so this is just a stub
    }
}

// Note that we wrap these in extern C as to not mangle the export names
extern "C"
{
    // Wow this is really cursed. Thank you MSVC for mangling exports.
    __declspec(dllexport) void __thiscall FakePacketDestructor(void* pThis) {
        return;
    }

    // ---------------------------------------------------------
    // Unimplemented stubs
    // ---------------------------------------------------------
    __declspec(dllexport) void pso2hGGCRCBypass() {}
    __declspec(dllexport) void pso2hExecuteFunction() {}
    __declspec(dllexport) int isGGReady() { return 1; }
    __declspec(dllexport) int pso2hGetVersion() { return 1000; }
    __declspec(dllexport) int pso2hCheckVersion() { return 1; }

    // ---------------------------------------------------------
    // Lua Engine hook
    // ---------------------------------------------------------
    __declspec(dllexport) void __cdecl pso2hDoLua(const char* script)
    {
       if (!script) {
            Log("[API-LUA] Received a NULL script.");
            return;
        }

        std::lock_guard<std::mutex> lock(g_LuaMutex);
        g_LuaQueue.push(script);
        
        if (g_LuaEvent) {
            SetEvent(g_LuaEvent);
            Log(std::string("[API-LUA] Script queued for execution:\n") + script);
        } else {
            Log("[API-LUA] WARNING: Lua Event not yet created! Script queued but may not execute immediately.");
        }
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
        uint16_t packetId = (subId << 8) + mainId;

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
        uint16_t packetId = (subId << 8) + mainId;

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