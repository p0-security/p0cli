# See https://nodejs.org/docs/latest-v20.x/api/single-executable-applications.html for more information.
# Some of these commands only work on macOS. Windows and Linux require slightly different commands.
node --experimental-sea-config sea-config.json 
cp $(command -v node) ./build/p0
codesign --remove-signature ./build/p0
npx postject ./build/p0 NODE_SEA_BLOB ./build/p0.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA 
codesign --sign - ./build/p0 