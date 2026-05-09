#pragma once
#include <windows.h>

namespace Scanner {
    void* FindPattern(const char* pattern, const char* mask);
    void* ResolveCall(void* address);
}