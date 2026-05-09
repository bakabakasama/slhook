#pragma once
#include <cstdint>
#include <map>
#include <vector>
#include <string>
#include <mutex>

// Structure to hold the plugin's callback pointer and its name for logging
struct PacketHandler {
    void* callback;
    std::string name;
};

// Global registries
extern std::map<uint16_t, std::vector<PacketHandler>> g_SendHandlers;
extern std::map<uint16_t, std::vector<PacketHandler>> g_RecvHandlers;
extern std::vector<PacketHandler> g_SendAllHandlers;
extern std::vector<PacketHandler> g_RecvAllHandlers;
// Allow network.cpp to see the IP parsed by your loader/config
extern std::string g_ProxyIP;

// Mutex to ensure thread-safe registrations and executions
extern std::recursive_mutex g_NetworkMutex;

// Hook Initialization
void InitializeNetworkHooks();