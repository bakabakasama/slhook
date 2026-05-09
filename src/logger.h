#pragma once
#include <string>

// Internal logging
void Log(const std::string& message);

// Exported logging used by the plugins (and our own internal API stubs)
extern "C" void pso2hLogLine(const char* format, ...);