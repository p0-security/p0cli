#!/usr/bin/env node

const esbuild = require("esbuild");

// This is used as part of the build process to create a single executable SEA binary.
// See https://nodejs.org/api/single-executable-applications.html#single-executable-applications
esbuild
  .build({
    entryPoints: ["./build/dist/index.js"],
    // Bundling is the primary reason for adding esbuild, as Node-SEA only allows for a
    // single script to be included in the binary. This means we need an extra step to
    // convert everything into one file, and use that file as the entrypoint to the final binary.
    bundle: true,
    platform: "node",
    target: "node20",
    // SEA does not support an ESM entrypoint script, so we need to output CommonJS
    format: "cjs",
    outfile: "build/sea/p0.js",
  })
  .then(() => {
    console.log("Bundling succeeded.");
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
