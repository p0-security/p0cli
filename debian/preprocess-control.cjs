/**
 * Injects the version from package.json into the control file.
 * The control file is the Debian build configuration file for application packaging.
 */
const fs = require("fs");
const path = require("path");

// Find package.json in the directory above
const packageJsonPath = path.resolve(__dirname, "..", "package.json");
const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
const version = pkg.version;

if (!version) {
  console.error('Error: No "version" field found in package.json.');
  process.exit(1);
}

// Inject version into control file
try {
  const controlPath = path.resolve(__dirname, "control");

  let content = fs.readFileSync(controlPath, "utf-8");
  const updatedContent = content.replace(/__VERSION__/g, version);

  fs.writeFileSync(controlPath, updatedContent);
  console.log(`Injected version ${version} into ${controlPath}`);
} catch (err) {
  console.error(`Error processing file: ${err.message}`);
  process.exit(1);
}
