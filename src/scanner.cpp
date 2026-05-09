#include "scanner.h"
#include <psapi.h>
#include <cstdint>

void* Scanner::FindPattern(const char* pattern, const char* mask) {
    MODULEINFO mInfo = { 0 };
    HMODULE hModule = GetModuleHandleA(NULL); // NULL gets the main .exe (pso2.exe)
    
    if (hModule == NULL) return nullptr;

    // We need psapi for this. 
    // In modern Windows, this is in kernel32, but MinGW often still needs -lpsapi
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &mInfo, sizeof(mInfo))) {
        return nullptr;
    }

    uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)mInfo.SizeOfImage;
    size_t patternLength = strlen(mask);

    for (uintptr_t i = 0; i < size - patternLength; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLength; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return (void*)(base + i);
    }
    return nullptr;
}

void* Scanner::ResolveCall(void* address) {
    if (!address) return nullptr;
    unsigned char* ptr = (unsigned char*)address;
    
    // In x86, a relative call (E8) is: E8 [4-byte relative offset]
    // The offset is relative to the address of the NEXT instruction.
    if (ptr[0] == 0xE8) {
        int32_t offset = *(int32_t*)(ptr + 1);
        return (void*)(ptr + 5 + offset);
    }
    
    return address; // Not a call, return original
}