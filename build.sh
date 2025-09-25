#!/bin/bash
# Tiger-Fox Build Script

set -e

echo "🚀 Building Tiger-Fox..."

mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "✅ Build completed! Run ./tiger-fox"