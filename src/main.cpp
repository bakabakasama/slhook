#include <windows.h>
#include "loader.h"
#include "logger.h"
#include "network.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            
            DeleteFileA("pso2h.log");
            
            // 1. Load the plugins and let them register their callbacks
            LoadPlugins();
            
            // 2. Turn the key and start intercepting packets!
            InitializeNetworkHooks();
            
            break;
        }
        case DLL_PROCESS_DETACH:
            // Optional: Unhook MinHook here if you want to be extra clean
            // MH_DisableHook(MH_ALL_HOOKS);
            // MH_Uninitialize();
            break;
    }
    return TRUE;
}