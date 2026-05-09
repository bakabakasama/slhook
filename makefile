CXX = i686-w64-mingw32-g++
CC = i686-w64-mingw32-gcc

# Add the vendor include directory so our C++ files can #include "MinHook.h"
CXXFLAGS = -O2 -Wall -std=c++14 -Iexternal/minhook/include
CFLAGS = -O2 -Wall -Iexternal/minhook/include

# The static linkage flags we fixed earlier
LDFLAGS = -static -static-libgcc -static-libstdc++ -Wl,--enable-stdcall-fixup -Wl,--kill-at -lws2_32 -lshlwapi -lpsapi

# Target directory for the final DLL
OUT_DIR = bin
TARGET = $(OUT_DIR)/pso2h.dll

# Find our C++ files
CXX_SRCS = $(wildcard src/*.cpp)
# Find the MinHook C files (Note: we only need hde32.c since PSO2 is a 32-bit game)
C_SRCS = external/minhook/src/buffer.c \
         external/minhook/src/hook.c \
         external/minhook/src/trampoline.c \
         external/minhook/src/hde/hde32.c

# Convert source names to object names
OBJS = $(CXX_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

all: $(TARGET)

# Ensure the output directory exists before linking
$(TARGET): $(OBJS) | $(OUT_DIR)
	$(CXX) -shared -o $@ $(OBJS) $(LDFLAGS)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o external/minhook/src/*.o external/minhook/src/hde/*.o
	rm -rf $(OUT_DIR)
