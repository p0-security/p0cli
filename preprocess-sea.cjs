const fs = require("fs");
const path = require("path");

// Get OS and architecture from command line arguments
const os = process.argv[2];
const arch = process.argv[3];

if (!os || !arch) {
  console.error("Error: Both os and arch arguments are required.");
  console.error("Usage: node preprocess-sea.cjs <os> <arch>");
  process.exit(1);
}

// Read package.json
const packageJsonPath = path.resolve(__dirname, "package.json");

try {
  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));

  // Add build metadata
  pkg.$build = {
    os,
    arch,
  };

  // Write back to package.json with formatting
  fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2) + "\n");

  console.log(`Added build metadata to package.json: os=${os}, arch=${arch}`);
} catch (err) {
  console.error(`Error modifying package.json: ${err.message}`);
  process.exit(1);
}
