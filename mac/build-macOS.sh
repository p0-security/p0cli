# See https://nodejs.org/docs/latest-v20.x/api/single-executable-applications.html for more information.
node --enable-fips --experimental-sea-config sea-config.json 
cp $(node -p process.execPath) ./build/sea/p0
codesign --remove-signature ./build/sea/p0
npx postject ./build/sea/p0 NODE_SEA_BLOB ./build/sea/p0.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA 
codesign --sign - ./build/sea/p0 