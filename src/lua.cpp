#include "lua.h"
#include "logger.h"
#include "MinHook.h"
#include <windows.h>
#include <cstdio>
#include "scanner.h"
#include <iostream>
#include <thread>

std::queue<std::string> g_LuaQueue;
std::mutex g_LuaMutex;
HANDLE g_LuaEvent = NULL;

// ---------------------------------------------------------
// Engine Lua Execution
// ---------------------------------------------------------
typedef int (__cdecl *LUA_LOADBUFFER)(void* L, const char* buff, size_t sz, const char* name);
typedef int (__cdecl *LUA_PCALL)(void* L, int nargs, int nresults, int errfunc);
LUA_LOADBUFFER oLuaLoadBuffer = nullptr;
LUA_PCALL oLuaPCall = nullptr;
void* g_EngineLuaState = nullptr; // We'll need to capture the global Lua state pointer!

int __cdecl DetourLuaLoadBuffer(void* L, const char* buff, size_t sz, const char* name) {
    // Capture Lua State just in case Parser hasn't caught it yet!
    if (!g_EngineLuaState && L != nullptr) {
        g_EngineLuaState = L;
        Log("[LUA] Successfully captured Engine Lua State from LoadBuffer!");
    }

    // We removed the aggressive script logging here so it doesn't
    // flood the interactive developer console!
    return oLuaLoadBuffer(L, buff, sz, name);
}

typedef BOOL (WINAPI *PEEK_MESSAGE_W)(LPMSG, HWND, UINT, UINT, UINT);
typedef BOOL (WINAPI *PEEK_MESSAGE_A)(LPMSG, HWND, UINT, UINT, UINT);
PEEK_MESSAGE_W oPeekMessageW = nullptr;
PEEK_MESSAGE_A oPeekMessageA = nullptr;

void ProcessLuaQueue() {
    if (g_LuaEvent && WaitForSingleObject(g_LuaEvent, 0) == WAIT_OBJECT_0) {
        // Do not process the queue if the Lua runtime is not fully captured yet!
        // Returning here leaves the event signaled, so we'll try again next tick.
        if (!oLuaLoadBuffer || !oLuaPCall || !g_EngineLuaState) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_LuaMutex);
        while (!g_LuaQueue.empty()) {
            std::string script = g_LuaQueue.front();
            g_LuaQueue.pop();
            
            Log(std::string("[LUA] Executing queued script:\n") + script);
            if (oLuaLoadBuffer(g_EngineLuaState, script.c_str(), script.length(), "pso2h") == 0) {
                int status = oLuaPCall(g_EngineLuaState, 0, 0, 0);
                if (status == 0) {
                    Log("[LUA] Script executed successfully!");
                } else {
                    Log("[LUA] ERROR: lua_pcall failed with status code: " + std::to_string(status));
                }
            } else {
                Log("[LUA] ERROR: luaL_loadbuffer failed to parse the script!");
            }
        }
        ResetEvent(g_LuaEvent);
    }
}

BOOL WINAPI DetourPeekMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) {
    ProcessLuaQueue();
    return oPeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

BOOL WINAPI DetourPeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg) {
    ProcessLuaQueue();
    return oPeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

// ---------------------------------------------------------
// Developer Console REPL
// ---------------------------------------------------------
void LuaREPLThread() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);
    
    std::cout << "========================================\n";
    std::cout << "      PSO2 LUA INTERACTIVE REPL         \n";
    std::cout << "========================================\n";
    std::cout << "> ";
    
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty()) {
            std::lock_guard<std::mutex> lock(g_LuaMutex);
            g_LuaQueue.push(line);
            if (g_LuaEvent) SetEvent(g_LuaEvent);
        }
        std::cout << "> ";
    }
}

void InitializeLuaHooks() {
    Log("--- Initializing Lua Hooks ---");
    
    g_LuaEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_LuaEvent) {
        DWORD err = GetLastError();
        char buf[256];
        snprintf(buf, sizeof(buf), "[LUA] Failed to create hook Event! (Error: %lu)", err);
        Log(buf);
    }

    // 2. Scan for lua_pcall
    // We use wildcards for the stack displacement bytes since they vary by calling convention
    const char* pcallPat = "\x56\x57\x55\x83\xEC\x08\x8B\x7C\x24\x00\x85\xFF\x8B\x74\x24\x00";
    const char* pcallMask = "xxxxxxxxx?xxxxx?";
    void* pCallTarget = Scanner::FindPattern(pcallPat, pcallMask);
    
    if (pCallTarget) {
        Log("[LUA] Found lua_pcall!");
        oLuaPCall = reinterpret_cast<LUA_PCALL>(pCallTarget);
    }

    // 3. Scan for luaL_loadbuffer
    // Allocates 8 bytes for LoadS, copies buff and size, pushes name, struct, getS, and L, then calls lua_load
    const char* loadPat = "\x83\xEC\x08\x8B\x44\x24\x10\x8D\x0C\x24\x8B\x54\x24\x14\x89\x04\x24\x89\x54\x24\x04\xFF\x74\x24\x18\x51\x68";
    const char* loadMask = "xxxxxxxxxxxxxxxxxxxxxxxxxxx";
    void* pLoadTarget = Scanner::FindPattern(loadPat, loadMask);
    
    if (pLoadTarget) {
        Log("[LUA] Found luaL_loadbuffer! Hooking to intercept scripts...");
        MH_CreateHook(pLoadTarget, (LPVOID)&DetourLuaLoadBuffer, reinterpret_cast<LPVOID*>(&oLuaLoadBuffer));
    }

    if (oLuaLoadBuffer && oLuaPCall) {
        Log("[LUA] Successfully resolved all Lua Execution API functions! Queue active.");
    } else {
        Log("[LUA] WARNING: Missing luaL_loadbuffer or lua_pcall!");
    }

    if (MH_CreateHookApi(L"user32.dll", "PeekMessageW", (LPVOID)&DetourPeekMessageW, reinterpret_cast<LPVOID*>(&oPeekMessageW)) == MH_OK) {}
    if (MH_CreateHookApi(L"user32.dll", "PeekMessageA", (LPVOID)&DetourPeekMessageA, reinterpret_cast<LPVOID*>(&oPeekMessageA)) == MH_OK) {}
    
    MH_EnableHook(MH_ALL_HOOKS);

    // Spawn the interactive developer console
    // std::thread(LuaREPLThread).detach();
}