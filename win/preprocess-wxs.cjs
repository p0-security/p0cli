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

if (!Array.isArray(version.split(".")) || version.split(".").length != 3) {
  console.error('Error: "version" field in package.json must have 3 segments (major.minor.patch).');
  process.exit(1);
}

// MSI versions typically have 4 segments, but we use 3 from package.json and append ".0"
const msiVersion = `${version}.0`;

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
