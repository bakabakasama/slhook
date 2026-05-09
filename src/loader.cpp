#include "loader.h"
#include "logger.h"
#include "config.h"
#include <windows.h>
#include <shlwapi.h>

void LoadPlugins() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    std::string pluginDir = "Plugins\\";
    std::string searchPath = pluginDir + "*.dll";

    Log("Scanning for plugins in " + pluginDir);

    hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        Log("Failed to open directory: " + pluginDir);
        return;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::string fileName = findData.cFileName;
        std::string fullPath = pluginDir + fileName;

        // Parse corresponding .cfg if it exists
        std::string configPath = fullPath;
        size_t lastDot = configPath.find_last_of(".");
        if (lastDot != std::string::npos) {
            configPath = configPath.substr(0, lastDot) + ".cfg";
        }

        if (PathFileExistsA(configPath.c_str())) {
            ParseConfigFile(configPath);
        }

        Log("Loading plugin: " + fileName);
        HMODULE hPlugin = LoadLibraryA(fullPath.c_str());

        if (hPlugin) {
            Log("Successfully loaded " + fileName);
        } else {
            Log("Failed to load " + fileName + " (Error: " + std::to_string(GetLastError()) + ")");
        }

    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}