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
    footer: {
      js: `
// This is a workaround to suppress deprecation warnings in the SEA binary
// without having to run NODE_OPTIONS='--no-deprecation' p0 [...args]
// Without this, the SEA binary will emit deprecation warnings that may be
// confusing to users
(() => {
  const originalEmit = process.emit;
  process.emit = function (name, data, ...args) {
    if (typeof data === 'object' && data.name === 'DeprecationWarning') {
      return false;
    }
    return originalEmit.apply(process, arguments);
  };
})();
      `,
    },
  })
  .then(() => {
    console.log("Bundling succeeded.");
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
