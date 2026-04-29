const fs = require("fs");
const path = require("path");
const uuid = require("uuid");

// Find package.json in the directory above
const packageJsonPath = path.resolve(__dirname, "..", "package.json");
const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
const version = pkg.version;
if (!version) {
  console.error('Error: No "version" field found in package.json.');
  process.exit(1);
}

// Strip pre-release suffix for the numeric part (e.g. "0.26.1-alpha.3" -> "0.26.1").
// WiX ProductVersion only accepts numeric major.minor.patch.build format.
const [numericVersion, preRelease] = version.split("-");

if (!Array.isArray(numericVersion.split(".")) || numericVersion.split(".").length != 3) {
  console.error('Error: "version" field in package.json must have 3 numeric segments (major.minor.patch).');
  process.exit(1);
}

// Use the trailing number from the pre-release suffix as the MSI build segment, if present.
// e.g. "alpha.3" -> 3, "dev" -> 0, no suffix -> 0
const buildNumber = preRelease ? (preRelease.match(/\d+$/) ?? [0])[0] : 0;
const msiVersion = `${numericVersion}.${buildNumber}`;

// This is a fixed UUID namespace for the product ID generation
// The product ID is deterministically generated from the namespace and the MSI version name
// Wix requires all builds with the same MSI version to have the same product ID but builds of
// different MSI versions to have different product IDs. UUID v5 is used to achieve this.
const p0cliUuidNamespace = "8A4226CB-FF7D-4BE0-B7AB-EEF047776584"; 
const name = msiVersion;
const productId = uuid.v5(name, p0cliUuidNamespace);

// Inject MSI version into p0.wxs file
try {
  const fullPath = path.resolve(__dirname, "p0.wxs");
  let content = fs.readFileSync(fullPath, "utf-8");
  const updatedContent = content
    .replace(/__VERSION__/g, msiVersion)
    .replace(/__PRODUCT_ID__/g, productId);

  fs.writeFileSync(fullPath, updatedContent);
  console.log(`Injected version ${msiVersion} and product ID ${productId} into ${fullPath}`);
} catch (err) {
  console.error(`Error processing file: ${err.message}`);
  process.exit(1);
}
