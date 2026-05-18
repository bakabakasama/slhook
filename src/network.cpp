#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <cstdint>
#include <string>
#include <cstdio>
#include <queue>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
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
// Crash handler (this is literally pso2itemtranslator's fault)
// ---------------------------------------------------------
// LONG WINAPI PluginCrashFilter(EXCEPTION_POINTERS *ep) {
//     // Intercept Access Violations (Code 0xC0000005)
//     if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        
//         uint8_t* eip = (uint8_t*)ep->ContextRecord->Eip;
//         if (eip)
//         {
//             // Crash 1: "movb (%esi), %al" -> Machine Code: 8A 06 (2 bytes)
//             if (eip[0] == 0x8A && eip[1] == 0x06)
//             {

//                 // Advance the Instruction Pointer by 2 bytes to skip the faulting instruction
//                 ep->ContextRecord->Eip += 2;

//                 // Force the AL register to 0x00. 
//                 // This tricks the plugin into thinking it hit the end of the string!
//                 ep->ContextRecord->Eax &= 0xFFFFFF00;

//                 // 3. Tell Windows/Wine to seamlessly resume execution as if nothing happened!
//                 return EXCEPTION_CONTINUE_EXECUTION;
//             }

//             // Crash 2: "movb -8(%ecx, %eax), %al" -> Machine Code: 8A 44 xx F8 (4 bytes)
//             // eip[0] == 8A (mov r8, r/m8)
//             // eip[1] == 44 (ModR/M byte for SIB + disp8)
//             // eip[3] == F8 (The -8 displacement)
//             if (eip[0] == 0x8A && eip[1] == 0x44 && eip[3] == 0xF8)
//             {
//                 ep->ContextRecord->Eip += 4; // Skip the 4-byte instruction
//                 ep->ContextRecord->Eax &= 0xFFFFFF00; // Force AL to 0x00
//                 return EXCEPTION_CONTINUE_EXECUTION;
//             }

//             // Crash 3: "rep movsb" -> Machine Code: F3 A4 (2 bytes)
//             // The plugin is trying to copy a garbage length. 
//             if (eip[0] == 0xF3 && eip[1] == 0xA4) {
//                 ep->ContextRecord->Eip += 2; // Skip the instruction
//                 ep->ContextRecord->Ecx = 0;  // Trick the CPU into thinking the copy finished
//                 return EXCEPTION_CONTINUE_EXECUTION;
//             }
//         }
//     }
    
//     // If it's a different kind of crash, fallback to the standard abort behavior
//     return EXCEPTION_CONTINUE_SEARCH;
//}

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
typedef void (__fastcall *ENGINE_RECV)(void* pThis, void* edx, char* rawBuffer);
typedef void (__fastcall *ENGINE_SEND)(void* pThis, void* edx, char* rawBuffer, void* unknownArg);

ENGINE_RECV oRecv = nullptr;
ENGINE_SEND oSend = nullptr;

// ---------------------------------------------------------
// Engine Detours
// ---------------------------------------------------------
void __fastcall DetourRecv(void* pThis, void* edx, char* rawBuffer)
{
    char* currentPacket = rawBuffer;

    // Process the data BEFORE the engine consumes/frees it
    if (currentPacket)
    {
        // Read directly from the raw memory array
        uint32_t rawTotalSize = *(uint32_t*)(currentPacket);
        // Only parse if we have a reasonable amount of data
        if (rawTotalSize >= 8 && rawTotalSize <= 8192 )
        {
            // Get packet ID
            uint16_t packetId = *(uint16_t*)(currentPacket + 4);
            std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
            auto it = g_RecvHandlers.find(packetId);
            if (it != g_RecvHandlers.end())
            {
                for (auto& handler : it->second)
                {
                    if (!currentPacket) break;
                    auto cb = reinterpret_cast<pktHandler>(handler.callback);
                    cb((uint8_t**)&currentPacket);
                }
            }
        }
        for (auto& handler : g_RecvAllHandlers)
        {
            if (!currentPacket) break;
            auto cb = reinterpret_cast<pktHandler>(handler.callback);
            cb((uint8_t**)&currentPacket);
        }
    }
    
    // Resume original game execution
    if (currentPacket)
    {
        oRecv(pThis, edx, currentPacket);
    }
}

void __fastcall DetourSend(void* pThis, void* edx, char* rawBuffer, void* unknownArg)
{
    char* currentPacket = rawBuffer;

    if (currentPacket)
    {
        uint32_t rawTotalSize = *(uint32_t*)(currentPacket);
        if (rawTotalSize >= 8 && rawTotalSize <= 8192)
        {
            uint16_t packetId = *(uint16_t*)(currentPacket + 4);
            std::lock_guard<std::recursive_mutex> lock(g_NetworkMutex);
            auto it = g_SendHandlers.find(packetId);
            if (it != g_SendHandlers.end())
            {
                for (auto& handler : it->second)
                {
                    if (!currentPacket) break;
                    auto cb = reinterpret_cast<pktHandler>(handler.callback);
                    cb((uint8_t**)&currentPacket);
                }
            }
        }
        for (auto& handler : g_SendAllHandlers)
        {
            if (!currentPacket) break;
            auto cb = reinterpret_cast<pktHandler>(handler.callback);
            cb((uint8_t**)&currentPacket);
        }
    }
    
    if (currentPacket)
    {
        oSend(pThis, edx, currentPacket, unknownArg);
    }
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
    // By prepending two wildcard bytes, we capture the two `push` instructions 
    // that happen right before `sub esp, 0Ch`, putting the hook at the TRUE start of the function!
    const char* sendPat = "\x00\x00\x83\xEC\x0C\x8B\xD1\x8B\x44\x24\x18\x83\x7C\x24\x1C\x00";
    const char* sendMask = "??xxxxxxxxxxxxxx";
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

    // // 3. Winsock Spoof
    // HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");

    // // There's a chance it might not be loaded at this point. Pre-load the DLL
    // if (!hWinsock) hWinsock = LoadLibraryA("ws2_32.dll");

    // // We're loaded. Hook the thingy
    // if (hWinsock)
    // {
    //     void* pGetAddrInfo = (void*)GetProcAddress(hWinsock, "getaddrinfo");
    //     if (pGetAddrInfo)
    //     {
    //         MH_CreateHook(pGetAddrInfo, (LPVOID)&DetourWinsockGetAddrInfo, reinterpret_cast<LPVOID*>(&oWinsockGetAddrInfo));
    //     }
    // } else {
    //     Log("[HOOKS] WARNING: Could not load ws2_32.dll for hooking!");
    // }

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

    // 5. Enable All
    MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
    Log(std::string("Hook Status: ") + MH_StatusToString(status));
}