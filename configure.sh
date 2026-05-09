#!/bin/bash
echo "--- Configuring Build Environment ---"

# Create the build directory
mkdir -p build

# Make our toolchain file
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../mingw32.cmake -DCMAKE_BUILD_TYPE=Release ..

echo "-----------------------------------"
echo "Configuration complete!"
echo "Run: cmake --build build"
echo "----------------------------------"