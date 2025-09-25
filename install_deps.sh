#!/bin/bash
# Tiger-Fox C++ Dependencies Installation Script
# Ubuntu 20.04+ required

set -e

echo "🔧 Installing Tiger-Fox C++ dependencies..."

# System packages
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    nlohmann-json3-dev \
    libpcre2-dev \
    libpcre2-8-0 \
    iptables-persistent \
    net-tools

# Verify installations
echo "📋 Verifying installations..."

# Check compiler
g++ --version
cmake --version

# Check libraries
pkg-config --exists libnetfilter_queue && echo "✅ libnetfilter_queue found" || echo "❌ libnetfilter_queue missing"
pkg-config --exists libpcre2-8 && echo "✅ libpcre2 found" || echo "❌ libpcre2 missing"

# Check nlohmann-json
if [ -f /usr/include/nlohmann/json.hpp ]; then
    echo "✅ nlohmann-json found"
else
    echo "❌ nlohmann-json missing"
fi

echo "🎯 All dependencies installed successfully!"
echo "Run: mkdir build && cd build && cmake .. && make"
