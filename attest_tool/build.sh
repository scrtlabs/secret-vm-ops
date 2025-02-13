#!/bin/bash

# Exit on any error
set -e

echo "Starting build process..."

# Check if script is run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script requires sudo privileges to install packages."
    echo "Please run with sudo."
    exit 1
fi

# Install required package
echo "Installing libtdx-attest-dev package..."
if ! apt install -y libtdx-attest-dev; then
    echo "Error: Failed to install libtdx-attest-dev"
    exit 1
fi
echo "Package installation successful."

# Check if source file exists
if [ ! -f "attest_tool.cpp" ]; then
    echo "Error: attest_tool.cpp not found"
    exit 1
fi

# Compile the code
echo "Compiling attest_tool.cpp..."
if ! gcc -O2 attest_tool.cpp -ltdx_attest -o attest_tool; then
    echo "Error: Compilation failed"
    exit 1
fi

echo "Build completed successfully!"
echo "Binary created: attest_tool"
