#!/bin/bash
# Build script for TrustFix GitHub Action

set -e

echo "🔨 Building TrustFix GitHub Action..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Build with ncc
echo "🏗️ Compiling with @vercel/ncc..."
npm run build

# Verify dist directory exists
if [ ! -d "dist" ]; then
  echo "❌ Build failed: dist/ directory not found"
  exit 1
fi

# Verify index.js exists
if [ ! -f "dist/index.js" ]; then
  echo "❌ Build failed: dist/index.js not found"
  exit 1
fi

echo "✅ Build complete!"
echo "📁 Output: dist/index.js"
echo ""
echo "Next steps:"
echo "1. Commit dist/ directory to repository"
echo "2. Create a release tag (e.g., v1.0.0)"
echo "3. Submit to GitHub Marketplace"
