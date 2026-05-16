#pragma once
#include <cstdint>
#include <map>
#include <vector>
#include <string>
#include <mutex>

// Definitions for packets (I have no idea if these are right but)
#pragma pack(push, 1)
struct PacketHeader {
    uint32_t size;
    uint8_t type;
    uint8_t subtype;
    uint8_t flags;
    uint8_t padding;
};
#pragma pack(pop)

// Packet snapshot
struct ProxyPacket {
    uint16_t id;
    std::vector<uint8_t> data;
};

// Structure to hold the plugin's callback pointer and its name for logging
struct PacketHandler {
    void* callback;
    std::string name;
};

class Packet {
public:
    void* ref;            // +0x00
    PacketHeader* header;  // +0x04
    uint16_t pktID;       // +0x08
    // (2 bytes of implicit padding here)
    uint32_t dataSize;    // +0x0C
    uint8_t* data;        // +0x10

    Packet(uint8_t** packet)
    {
        ref = reinterpret_cast<void*>(packet);
        uint8_t* rawBuffer = *packet;
        header = reinterpret_cast<PacketHeader*>(rawBuffer);
        // ID is constructed as (Subtype << 8) | Type to match 
        // the Little-Endian memory read (e.g., 0x5204)
        pktID = (header->subtype << 8) | header->type; 
        dataSize = header->size - 8;
        data = rawBuffer + 8;
    }
};

// Revert to __cdecl to match the original plugin specifications
typedef void (__cdecl *pktHandler)(uint8_t** packet);

// Global registries
extern std::map<uint16_t, std::vector<PacketHandler>> g_SendHandlers;
extern std::map<uint16_t, std::vector<PacketHandler>> g_RecvHandlers;
extern std::vector<PacketHandler> g_SendAllHandlers;
extern std::vector<PacketHandler> g_RecvAllHandlers;
// Allow network.cpp to see the IP parsed by your loader/config
extern std::string g_ProxyIP;
extern std::string g_ProxyHostname;

// Mutex to ensure thread-safe registrations and executions
extern std::recursive_mutex g_NetworkMutex;

// Define some functions
void InitializeNetworkHooks();
std::string ResolveHostnameToIP(const std::string& inputHost);