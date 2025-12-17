#!/bin/bash
set -e  # Exit on any error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "===== Building P0 CLI Binary ====="
# See https://nodejs.org/docs/latest-v20.x/api/single-executable-applications.html for more information.
node --experimental-sea-config sea-config.json
cp $(node -p process.execPath) ./build/sea/p0
codesign --remove-signature ./build/sea/p0
npx postject ./build/sea/p0 NODE_SEA_BLOB ./build/sea/p0.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA
codesign --sign - ./build/sea/p0

echo ""
echo "===== Building P0 URL Handler ====="

# Check if xcodebuild is available
if ! command -v xcodebuild &> /dev/null; then
    echo "Error: xcodebuild not found."
    echo ""
    echo "This build script requires Xcode to be installed."
    echo "Please install Xcode from the App Store or download it from:"
    echo "https://developer.apple.com/xcode/"
    echo ""
    echo "After installing Xcode, run:"
    echo "  sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer"
    echo ""
    exit 1
fi

# Output the final app to the root build directory
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
URL_HANDLER_OUTPUT_DIR="$REPO_ROOT/build"
# Use a temporary directory for DerivedData
URL_HANDLER_DERIVED_DATA_DIR="$URL_HANDLER_OUTPUT_DIR/DerivedData"


# Clean previous URL handler build
if [ -d "$URL_HANDLER_DERIVED_DATA_DIR" ]; then
    echo "Cleaning previous URL handler build..."
    rm -rf "$URL_HANDLER_DERIVED_DATA_DIR"
fi
if [ -d "$URL_HANDLER_OUTPUT_DIR/P0 CLI.app" ]; then
    echo "Removing previous P0 CLI.app from build directory..."
    rm -rf "$URL_HANDLER_OUTPUT_DIR/P0 CLI.app"
fi

# Build the URL handler app using xcodebuild
echo "Running xcodebuild for url-handler..."

# Check if the code signing certificate is available in the keychain
if [ -n "$APPLE_CODESIGN_CERT_NAME" ] && security find-identity -v -p codesigning | grep -q "$APPLE_CODESIGN_CERT_NAME"; then
    echo "Found code signing certificate in keychain: $APPLE_CODESIGN_CERT_NAME"
    echo "Building with Release configuration and manual code signing (Development Team: $APPLE_DEVELOPER_TEAM)"
    BUILD_CONFIGURATION="Release"
else
    echo "Code signing certificate not found in keychain"
    echo "Building with Debug configuration and ad-hoc signing for local development"
    BUILD_CONFIGURATION="Debug"
fi

# Build with appropriate configuration
if [ "$BUILD_CONFIGURATION" = "Release" ]; then
    xcodebuild \
        -project "$SCRIPT_DIR/url-handler.xcodeproj" \
        -scheme url-handler \
        -configuration "$BUILD_CONFIGURATION" \
        -derivedDataPath "$URL_HANDLER_DERIVED_DATA_DIR" \
        CODE_SIGN_STYLE="Manual" \
        CODE_SIGN_IDENTITY="$APPLE_CODESIGN_CERT_NAME" \
        DEVELOPMENT_TEAM="$APPLE_DEVELOPER_TEAM" \
        build
else
    xcodebuild \
        -project "$SCRIPT_DIR/url-handler.xcodeproj" \
        -scheme url-handler \
        -configuration "$BUILD_CONFIGURATION" \
        -derivedDataPath "$URL_HANDLER_DERIVED_DATA_DIR" \
        build
fi

# Copy the built app to the root build directory
echo "Copying built URL handler app to root build directory..."
mkdir -p "$URL_HANDLER_OUTPUT_DIR"
cp -R "$URL_HANDLER_DERIVED_DATA_DIR/Build/Products/$BUILD_CONFIGURATION/P0 CLI.app" "$URL_HANDLER_OUTPUT_DIR/"

# Sign the app if not already signed by xcodebuild (local development only)
if [ "$BUILD_CONFIGURATION" = "Debug" ]; then
    echo "Applying ad-hoc signature to the URL handler app..."
    codesign --force --deep --sign - "$URL_HANDLER_OUTPUT_DIR/P0 CLI.app"
else
    echo "App signed by xcodebuild with certificate: $APPLE_CODESIGN_CERT_NAME"
fi

echo ""
echo "===== Build Complete ====="
echo "P0 CLI binary: ./build/sea/p0"
echo "P0 URL Handler: $URL_HANDLER_OUTPUT_DIR/P0 CLI.app"
echo "" 