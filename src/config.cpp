#include "config.h"
#include "logger.h"
#include <map>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstring> // Needed for strncpy
#include <windows.h>

// The global dictionary for all configuration variables
std::map<std::string, std::string> g_ConfigMap;
std::string g_ProxyIP = "127.0.0.1";

// Helper: Trim whitespace from both ends
void Trim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

// Helper: Remove the bracketed metadata (e.g., "[Y/N]" or "[path]")
void CleanKey(std::string& key) {
    size_t startBracket = key.find('[');
    if (startBracket != std::string::npos) {
        size_t endBracket = key.find(']', startBracket);
        if (endBracket != std::string::npos) {
            key.erase(startBracket, endBracket - startBracket + 1);
        } else {
            key.erase(startBracket);
        }
    }
    Trim(key);
}

// Helper: Remove leading and trailing quotes from the value
void CleanValue(std::string& value) {
    if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.length() - 2);
    }
}

// The main parsing function called by the loader thread
void ParseConfigFile(const std::string& filePath) {
    std::ifstream file(filePath);
    std::string line;
    
    if (!file.is_open()) return;

    while (std::getline(file, line)) {
        Trim(line);
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        
        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            Trim(key);
            Trim(value);
            CleanKey(key);
            CleanValue(value);
            
            if (!key.empty()) {
                g_ConfigMap[key] = value;
                // Log using our internal logger
                Log("Parsed Config -> " + key + " : " + value);

                // Store the config file because I'm lazy
                if (key == "proxy") {
                    g_ProxyIP = value;
                }
            }
        }
    }
}

extern "C" {
    // Exported function matching the original 3-argument ABI
    __declspec(dllexport) int pso2hGetConfig(const char* key, char* outBuffer, int maxLen) {
        auto it = g_ConfigMap.find(key);
        
        // If the key doesn't exist in our map, return 0 (not found)
        if (it == g_ConfigMap.end()) {
            return 0; 
        }

        const std::string& value = it->second;
        int requiredSize = value.length() + 1; // +1 for the null terminator

        // If the plugin passes NULL, they are querying how much memory they need to allocate
        if (outBuffer == nullptr || maxLen <= 0) {
            return requiredSize;
        }

        // Otherwise, they gave us a buffer. Copy the string safely!
        // We use maxLen - 1 to ensure we always have room to null-terminate it
        int copyLen = (value.length() < (size_t)(maxLen - 1)) ? value.length() : (maxLen - 1);
        strncpy(outBuffer, value.c_str(), copyLen);
        outBuffer[copyLen] = '\0'; // Guarantee null termination

        // Return the number of bytes we successfully copied
        return copyLen;
    }
}