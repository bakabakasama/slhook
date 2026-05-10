#include <windows.h>
#include "logger.h"
#include "loader.h"
#include "network.h"
#include "config.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            
            // Clean up old log file
            DeleteFileA("pso2h.log");
            
            // Initialize plugins
            LoadPlugins();
            
            // Check for our proxy.txt override
            LoadProxyOverride();

            // Initialize our network hooks
            InitializeNetworkHooks();
            
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}