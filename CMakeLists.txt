# CMakeLists.txt
cmake_minimum_required(VERSION 3.13)

# Definitions
project(PSO2Proxy VERSION 1.0 LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# This the stuff
file(GLOB CXX_SRCS "src/*.cpp")

# MinHook
set(MINHOOK_SRCS
    "external/minhook/src/buffer.c"
    "external/minhook/src/hook.c"
    "external/minhook/src/trampoline.c"
    "external/minhook/src/hde/hde32.c"
)

# ---------------------------------------------------------
# Target: pso2h.dll
# ---------------------------------------------------------
# Make a shared library (.dll)
add_library(pso2h SHARED ${CXX_SRCS} ${MINHOOK_SRCS})

# Get rid of "lib" prefix
set_target_properties(pso2h PROPERTIES PREFIX "")

# Output to bin/
set_target_properties(pso2h PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Add include directory for MinHook headers
target_include_directories(pso2h PRIVATE external/minhook/include)

# Add Windows library links
target_link_libraries(pso2h PRIVATE ws2_32 shlwapi psapi)

# Apply linker flags to fix standard call
target_link_options(pso2h PRIVATE 
    -static 
    -static-libgcc 
    -static-libstdc++ 
    -Wl,--enable-stdcall-fixup 
    -Wl,--kill-at
)

# Warnings
target_compile_options(pso2h PRIVATE -Wall)