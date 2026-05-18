#pragma once
#include <windows.h>
#include <string>
#include <queue>
#include <mutex>

extern std::queue<std::string> g_LuaQueue;
extern std::mutex g_LuaMutex;
extern HANDLE g_LuaEvent;

void InitializeLuaHooks();
void ProcessLuaQueue();