#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
//#include <wininet.h>
#include <winhttp.h>
#include <cstdint>
#include <string>
#include <cstdio>
#include "MinHook.h"
#include "network.h"
#include "logger.h"
#include "scanner.h"

// ---------------------------------------------------------
// Global Network Registry Definition
// ---------------------------------------------------------
std::map<uint16_t, std::vector<PacketHandler>> g_SendHandlers;
std::map<uint16_t, std::vector<PacketHandler>> g_RecvHandlers;
std::vector<PacketHandler> g_SendAllHandlers;
std::vector<PacketHandler> g_RecvAllHandlers;
std::recursive_mutex g_NetworkMutex;

// ---------------------------------------------------------
// The Reversed 20-Byte Packet Struct
// ---------------------------------------------------------
#pragma pack(push, 1)
struct PSO2Packet {
    uint32_t size;
    uint8_t type;
    uint8_t subtype;
    uint8_t flags;
    uint8_t padding;    
};
#pragma pack(pop)

// ---------------------------------------------------------
// DNS Helper
// ---------------------------------------------------------
std::string ResolveHostnameToIP(const std::string& inputHost) {
    // Initialize Winsock if it hasn't been already
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Attempt to resolve the hostname
    struct hostent* he = gethostbyname(inputHost.c_str());
    if (he != nullptr) {
        // Grab the first IPv4 address from the resolution list
        struct in_addr** addr_list = (struct in_addr**)he->h_addr_list;
        if (addr_list[0] != nullptr) {
            // Store it
            std::string resolvedIp = inet_ntoa(*addr_list[0]);
            Log("[DNS] Resolved hostname '" + inputHost + "' -> " + resolvedIp);
            return resolvedIp;
        }
    }

    // If it fails (or if it was already a raw IP), just return the original string
    return inputHost;
}

// ---------------------------------------------------------
// Engine Signatures
// ---------------------------------------------------------
// The engine simply passes a pointer directly to the raw packet bytes.
typedef void (__thiscall *ENGINE_RECV)(void* pThis, char* rawBuffer);
typedef void (__thiscall *ENGINE_SEND)(void* pThis, char* rawBuffer);

ENGINE_RECV oRecv = nullptr;
ENGINE_SEND oSend = nullptr;

// ---------------------------------------------------------
// Engine Detours
// ---------------------------------------------------------
void __thiscall DetourRecv(void* pThis, char* rawBuffer)
{
    // Process the data BEFORE the engine consumes/frees it
    if (rawBuffer && !IsBadReadPtr(rawBuffer, 8))
    {
        
        // Read directly from the raw memory array
        uint32_t rawTotalSize = *(uint32_t*)(rawBuffer);
        uint16_t packetId = *(uint16_t*)(rawBuffer + 4);

        // Sanity Filter (Header must be at least 8 bytes)
        //if (rawTotalSize >= 8 && rawTotalSize < 100000) {
            uint32_t safePayloadSize = rawTotalSize - 8;

            // Hex Dumper (Reading the first 8 bytes of the raw buffer)
            uint8_t* b = (uint8_t*)rawBuffer;
            //char logBuf[512];
            //snprintf(logBuf, sizeof(logBuf), "[PROXY-RECV] ID: %04X | Size: %u | Hex: %02X %02X %02X %02X %02X %02X %02X %02X", 
            //         packetId, rawTotalSize, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            //Log(logBuf);

            std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
            
            auto it = g_RecvHandlers.find(packetId);
            if (it != g_RecvHandlers.end())
            {
                for (auto& handler : it->second)
                {
                    uint8_t* safeCopy = new uint8_t[rawTotalSize];
                    memcpy(safeCopy, rawBuffer, rawTotalSize);

                    auto cb = reinterpret_cast<pktHandler>(handler.callback);
                    cb(safeCopy);

                    delete[] safeCopy;
                }
            }

            for (auto& handler : g_RecvAllHandlers)
            {
                uint8_t* safeCopy = new uint8_t[rawTotalSize];
                memcpy(safeCopy, rawBuffer, rawTotalSize);

                auto cb = reinterpret_cast<pktHandler>(handler.callback);
                cb(safeCopy);

                delete[] safeCopy;
            }
        //}
    }
    
    // Resume original game execution
    oRecv(pThis, rawBuffer);
}

void __thiscall DetourSend(void* pThis, char* rawBuffer)
{
    if (rawBuffer && !IsBadReadPtr(rawBuffer, 8))
    {
        
        uint32_t rawTotalSize = *(uint32_t*)(rawBuffer);
        uint16_t packetId = *(uint16_t*)(rawBuffer + 4);
        Packet pkt(rawBuffer);

        //if (rawTotalSize >= 8 && rawTotalSize < 100000) {
            uint32_t safePayloadSize = rawTotalSize - 8;

            //char logBuf[512];
            //snprintf(logBuf, sizeof(logBuf), "[PROXY-SEND] ID: %04X | Size: %u", packetId, rawTotalSize);
            //Log(logBuf);

            std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);

            auto it = g_SendHandlers.find(packetId);
            if (it != g_SendHandlers.end())
            {
                for (auto& handler : it->second)
                {
                    uint8_t* safeCopy = new uint8_t[rawTotalSize];
                    memcpy(safeCopy, rawBuffer, rawTotalSize);

                    auto cb = reinterpret_cast<pktHandler>(handler.callback);
                    cb(safeCopy);

                    delete[] safeCopy;
                }
            }

            for (auto& handler : g_SendAllHandlers)
            {
                uint8_t* safeCopy = new uint8_t[rawTotalSize];
                memcpy(safeCopy, rawBuffer, rawTotalSize);

                auto cb = reinterpret_cast<pktHandler>(handler.callback);
                cb(safeCopy);

                delete[] safeCopy;
            }
        //}
    }
    
    oSend(pThis, rawBuffer);
}

// ---------------------------------------------------------
// Winsock Spoofing
// ---------------------------------------------------------
typedef int (WINAPI *WSA_GETADDRINFO)(const char* pNodeName, const char* pServiceName, const struct addrinfo* pHints, struct addrinfo** ppResult);
WSA_GETADDRINFO oWinsockGetAddrInfo = nullptr;

int WINAPI DetourWinsockGetAddrInfo(const char* pNodeName, const char* pServiceName, const struct addrinfo* pHints, struct addrinfo** ppResult)
{
    if (pNodeName && strstr(pNodeName, "pso2gs.net")) {
        // Use the config IP! If it's empty, fallback to localhost just in case.
        const char* targetIp = g_ProxyIP.empty() ? "127.0.0.1" : g_ProxyIP.c_str();
        
        char buf[256];
        snprintf(buf, sizeof(buf), "[WINSOCK] HIJACK TRIGGERED: Rerouting Sega DNS to %s", targetIp);
        Log(buf);
        
        return oWinsockGetAddrInfo(targetIp, pServiceName, pHints, ppResult);
    }
    return oWinsockGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

// ---------------------------------------------------------
// WinHTTP Spoofing
// ---------------------------------------------------------
typedef HINTERNET(WINAPI *WINHTTP_CONNECT_FN)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
WINHTTP_CONNECT_FN oWinHttpConnect = nullptr;

HINTERNET WINAPI DetourWinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
{
    
    // Convert the wide string (LPCWSTR) to a standard char array
    char serverNameBuf[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, pswzServerName, -1, serverNameBuf, sizeof(serverNameBuf), NULL, NULL);

    // Log on redirect
    char logBuf[512];
    snprintf(logBuf, sizeof(logBuf), "[WINHTTP] Intercepted connection to: %s:%d", serverNameBuf, nServerPort);
    Log(logBuf);

    // Convert our proxy into a wstring
    std::wstring wide_redirect(g_ProxyHostname.begin(), g_ProxyHostname.end());

    snprintf(logBuf, sizeof(logBuf), "[WINHTTP] Rerouting %s to proxy: %s", serverNameBuf, g_ProxyHostname.c_str());
    Log(logBuf);

    // Call the original Windows function, but pass our Proxy IP wide-string instead!
    return oWinHttpConnect(hSession, wide_redirect.c_str(), nServerPort, dwReserved);
}

// // ---------------------------------------------------------
// // WinINet Spoofing
// // ---------------------------------------------------------
// typedef HINTERNET(WINAPI *INTERNET_CONNECT_W)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
// INTERNET_CONNECT_W oInternetConnectW = nullptr;

// HINTERNET WINAPI DetourInternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, 
//                                         LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, 
//                                         DWORD dwFlags, DWORD_PTR dwContext)
//                                         {
    
//     // Convert the wide string (LPCWSTR) to a standard char array                                        
//     char serverNameBuf[256] = {0};
//     WideCharToMultiByte(CP_UTF8, 0, lpszServerName, -1, serverNameBuf, sizeof(serverNameBuf), NULL, NULL);

//     // Log on redirect
//     char logBuf[512];
//     snprintf(logBuf, sizeof(logBuf), "[WININET] Intercepted connection to: %s:%d", serverNameBuf, nServerPort);
//     Log(logBuf);

//     // Only hijack the download server! We don't want to break other background Windows tasks
//     //if (strstr(serverNameBuf, "download.pso2.jp") != nullptr) {
//     std::wstring proxyIpW(g_ProxyIP.begin(), g_ProxyIP.end());
//     Log("[WININET] Rerouting WinINet to proxy IP.");
//     return oInternetConnectW(hInternet, proxyIpW.c_str(), nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
//     //}

//     //return oInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
// }

// ---------------------------------------------------------
// Hook Initializer
// ---------------------------------------------------------
void InitializeNetworkHooks() {
    Log("--- Initializing Proxy Hooks ---");

    // 1. CRC Bypass
    uintptr_t exeBase = (uintptr_t)GetModuleHandleA(NULL);
    if (exeBase) {
        DWORD oldProtect;
        if (VirtualProtect((LPVOID)(exeBase + 0x34), 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(uint64_t*)(exeBase + 0x34) = 0; 
            VirtualProtect((LPVOID)(exeBase + 0x34), 8, oldProtect, &oldProtect);
            Log("CRC Checksum bypass applied.");
        }
    }

    MH_Initialize();

    // 2. Scan Engine Signatures (Masked)
    const char* sendPat = "\x83\xEC\x0C\x8B\xD1\x8B\x44\x24\x18\x83\x7C\x24\x1C\x00";
    const char* sendMask = "xxxxxxxxxxxxxx";
    void* pSendTarget = Scanner::FindPattern(sendPat, sendMask);

    const char* recvPat = "\x33\xD2\x8B\x44\x24\x04\x89\x91\x00\x00\x00\x00\x89\x91\x00\x00\x00\x00\x8B\x10";
    const char* recvMask = "xxxxxxxx????xx????xx";
    void* pRecvTarget = Scanner::FindPattern(recvPat, recvMask);

    if (pSendTarget && pRecvTarget) {
        MH_CreateHook(pSendTarget, (LPVOID)&DetourSend, reinterpret_cast<LPVOID*>(&oSend));
        MH_CreateHook(pRecvTarget, (LPVOID)&DetourRecv, reinterpret_cast<LPVOID*>(&oRecv));
    } else {
        Log("CRITICAL: Failed to find Send/Recv Engine patterns.");
    }

    // 3. Winsock Spoof
    HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");

    // There's a chance it might not be loaded at this point. Pre-load the DLL
    if (!hWinsock) hWinsock = LoadLibraryA("ws2_32.dll");

    // We're loaded. Hook the thingy
    if (hWinsock)
    {
        void* pGetAddrInfo = (void*)GetProcAddress(hWinsock, "getaddrinfo");
        if (pGetAddrInfo)
        {
            MH_CreateHook(pGetAddrInfo, (LPVOID)&DetourWinsockGetAddrInfo, reinterpret_cast<LPVOID*>(&oWinsockGetAddrInfo));
        }
    } else {
        Log("[HOOKS] WARNING: Could not load ws2_32.dll for hooking!");
    }

    // 4. WinHTTP Spoof
    HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
    // There's a chance it might not be loaded at this point. Pre-load the DLL
    if (!hWinHttp) hWinHttp = LoadLibraryA("winhttp.dll");
    // We're loaded. Go for the hook
    if (hWinHttp)
    {
        void* pWinHttpConnect = (void*)GetProcAddress(hWinHttp, "WinHttpConnect");
        if (pWinHttpConnect)
        {
            MH_CreateHook(pWinHttpConnect, (LPVOID)&DetourWinHttpConnect, reinterpret_cast<LPVOID*>(&oWinHttpConnect));
        }
    } else {
        Log("[HOOKS] WARNING: Could not load winhttp.dll for hooking!");
    }

    // // 5. WinINet Hook
    // HMODULE hWinINet = GetModuleHandleA("wininet.dll");
    // // Pre-load DLL
    // if (!hWinINet) hWinINet = LoadLibraryA("wininet.dll");
    // // Hook time
    // if (hWinINet)
    // {
    //     void* pInternetConnectW = (void*)GetProcAddress(hWinINet, "InternetConnectW");
    //     if (pInternetConnectW) {
    //         MH_CreateHook(pInternetConnectW, (LPVOID)&DetourInternetConnectW, reinterpret_cast<LPVOID*>(&oInternetConnectW));
    //     } else {
    //     Log("[HOOKS] WARNING: Could not load wininet.dll for hooking!");
    //     }
    // }

    // 5. Enable All
    MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
    Log(std::string("Hook Status: ") + MH_StatusToString(status));
}