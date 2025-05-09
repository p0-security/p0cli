#!/usr/bin/env node

const esbuild = require("esbuild");
esbuild
  .build({
    entryPoints: ["./build/dist/index.js"],
    bundle: true,
    platform: "node",
    target: "node20",
    format: "cjs",
    outfile: "build/p0.js",
  })
  .then(() => {
    console.log("Bundling succeeded.");
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });