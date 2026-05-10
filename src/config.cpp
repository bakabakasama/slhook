#include "config.h"
#include <map>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <windows.h>
#include "logger.h"

// Global variables
std::map<std::string, std::string> g_ConfigMap;
std::string g_ProxyIP = "127.0.0.1"; // Fallback IP

// Helper function to trim whitespace when reading
void Trim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

// Helper function to remove the "[]" brackets
void CleanKey(std::string& key)
{
    // Find start of bracket
    size_t startBracket = key.find('[');
    // If bracket exists...
    if (startBracket != std::string::npos)
    {
        // Find the end one
        size_t endBracket = key.find(']', startBracket);
        // If the end bracket exists...
        if (endBracket != std::string::npos) {
            // Erase both start and end bracket and everything inside
            key.erase(startBracket, endBracket - startBracket + 1);
        } else {
            // Just erase the start bracket
            // We probably don't need this, but whatever
            key.erase(startBracket);
        }
    }
    Trim(key);
}

// Helper function to remove leading and trailing quotes
void CleanValue(std::string& value)
{
    // Check if value is wrapped by quotes
    if (value.length() >= 2 && value.front() == '"' && value.back() == '"')
    {
        // Get rid of them
        value = value.substr(1, value.length() - 2);
    }
}

// The main parsing function called by the exported function below
void ParseConfigFile(const std::string& filePath)
{
    std::ifstream file(filePath);
    std::string line;
    
    // Why is the file not open
    if (!file.is_open()) return;

    // Parse time
    while (std::getline(file, line))
    {
        // Trim whitespace
        Trim(line);
        
        // Skip comments and empty lines (please don't comment your config files)
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        
        // Find the = delimiter to separate key and value
        size_t delimiterPos = line.find('=');
        // If line has a delimiter...
        if (delimiterPos != std::string::npos)
        {
            // Break the strings apart
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            // Trim both of them
            Trim(key);
            Trim(value);
            CleanKey(key);
            CleanValue(value);
            
            // As long as there is a key, continue
            if (!key.empty())
            {
                g_ConfigMap[key] = value;
                // Log it
                Log("Parsed Config -> " + key + " : " + value);

                // Okay this is kinda dumb for now, but because we redirect
                // the networking ourselves, we can just rip the proxy key
                // out of TelepipeProxy.cfg and store it to use ourselves
                // if (key == "proxy")
                // {
                //     g_ProxyIP = value;
                // }
            }
        }
    }
}

// Loads the proxy override from proxy.txt
void LoadProxyOverride()
{
    // We are looking for proxy.txt here
    std::ifstream file("proxy.txt");
    std::string line;
    
    // Open it up, grab the line
    if (file.is_open() && std::getline(file, line)) 
    {
        // Trim it!
        Trim(line);
        if (!line.empty()) 
        {
            // Store it!
            g_ProxyIP = line;
            Log("[Loader] Proxy Override: Loaded Proxy IP from proxy.txt -> " + g_ProxyIP);
        }
    }
}

extern "C"
{
    // Exported function implementation
    __declspec(dllexport) int pso2hGetConfig(const char* key, char* outBuffer, int maxLen)
    {
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