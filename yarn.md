# Yarn Guide for P0 CLI

This guide covers Yarn usage patterns and best practices for the P0 CLI project.

## Yarn Version

This project uses **Yarn 1.22.22** (Yarn Classic), managed via the `packageManager` field in `package.json`. The version is automatically enforced when you run `yarn` commands.

## Installation

### Fresh Install

```bash
yarn install
```

### Using `--frozen-lockfile`

For CI/CD and production builds, use `--frozen-lockfile` to ensure consistent dependency resolution:

```bash
yarn install --frozen-lockfile
```

This flag:

- Prevents lock file updates during install
- Ensures reproducible builds across environments
- Fails if the lock file is out of sync with package.json

Using `--frozen-lockfile` is recommended for CI/CD pipelines to catch lock file drift early, but is optional for local development.

## Dependency Management

### DO

- **Leverage `devDependencies`** to minimize 3rd party software packaged with releases

  - Put build tools (esbuild, TypeScript), linters (ESLint, Prettier), and test frameworks (Vitest) in `devDependencies`
  - Only use `dependencies` for code that ships with the published CLI
  - This reduces security vulnerability surface area and package complexity in production bundles

- **Use `--frozen-lockfile` in CI/CD pipelines** to ensure reproducible builds
  - Prevents unexpected dependency changes during deployment or publishing
  - Catches lock file drift early

### DO NOT

- **Avoid pinning to specific versions** in `package.json` without good reason
  - Use semantic version ranges (`^1.2.3`) to allow patch and minor updates
  - Only pin (`1.2.3`) when you have a specific compatibility issue or security concern
  - Document the reason for pinning in a comment or commit message

### Helpful

- **Periodically run `yarn npm audit -F`** before committing
  - Note: This is a Yarn Modern command. For Yarn Classic (1.x), use `yarn audit` instead
  - Check if packages have known vulnerabilities
  - Identify available security patches and upgrades
  - Review the report before updating dependencies

## Common Commands

### Installation & Updates

```bash
# Install dependencies (use --frozen-lockfile in CI)
yarn install --frozen-lockfile

# Add a new dependency
yarn add <package-name>

# Add a new devDependency
yarn add -D <package-name>

# Remove a dependency
yarn remove <package-name>

# Upgrade a specific package
yarn upgrade <package-name>

# Upgrade a package to a specific version
yarn upgrade <package-name>@<version>

# Interactive upgrade (check for outdated packages)
yarn upgrade-interactive
```

### Build & Development

```bash
# Build the CLI
yarn build

# Run the CLI locally
yarn p0 <command>

# Run tests
yarn test

# Run all linting checks
yarn lint

# Format code
yarn format

# Clean build artifacts
yarn clean
```

### Platform-Specific Builds

```bash
# Build standalone executable for macOS
yarn build:macos
./mac/build-macOS.sh

# Build for Windows
yarn build:windows

# Build for Debian/Linux
yarn build:debian
```

## Security

### Audit Dependencies

```bash
# Run security audit (Yarn 1.x command)
yarn audit

# Check for outdated packages
yarn outdated
```

Before committing changes, especially dependency updates:

1. Run `yarn audit` to check for vulnerabilities
2. Review the audit report and address high/critical issues
3. Test the CLI thoroughly after updates

### Production Dependencies

The CLI is distributed as:

1. **npm package** - Users install globally with `npm install -g @p0security/cli`
2. **Standalone executables** - Single binary with bundled Node.js (macOS, Windows, Linux)

For the npm package, only `dependencies` are bundled. Keep this list minimal and audit regularly since users will download these packages.

## Upgrading Dependencies

### Check for Updates

```bash
# List outdated packages
yarn outdated

# Interactive upgrade tool
yarn upgrade-interactive --latest
```

### Upgrade Strategy

1. **Minor and patch updates**: Generally safe to upgrade with `^` ranges
2. **Major updates**: Review CHANGELOG and test thoroughly
3. **Security patches**: Prioritize and upgrade immediately

### After Upgrading

Always verify after upgrading:

```bash
# Reinstall with frozen lockfile
yarn install --frozen-lockfile

# Run all checks
yarn lint
yarn test

# Build and test the CLI
yarn build
yarn p0 --version
yarn p0 login --help
```

## Troubleshooting

### Lock File Conflicts

When merging branches with lock file conflicts:

```bash
# Accept one side (e.g., main branch)
git checkout main -- yarn.lock

# Regenerate lock file from package.json
yarn install

# Verify it installs correctly
yarn install --frozen-lockfile

# Commit the resolved lock file
git add yarn.lock
git commit -m "Resolve yarn.lock conflicts"
```

### Cache Issues

If you encounter mysterious installation issues:

```bash
# Clear Yarn cache
yarn cache clean

# Remove node_modules and reinstall
rm -rf node_modules
yarn install --frozen-lockfile
```

### Platform-Specific Issues

The CLI includes native Node.js dependencies that may require rebuilding:

```bash
# Rebuild native modules
yarn install --force

# On macOS with Apple Silicon
arch -arm64 yarn install --frozen-lockfile
```

## CI/CD Integration

Recommended CI/CD pattern for this project:

```bash
# Install dependencies
yarn install --frozen-lockfile

# Run linting
yarn lint

# Run tests
yarn test

# Build the CLI
yarn build

# For npm publishing (automated via GitHub Actions)
yarn prepublishOnly
```

Using `--frozen-lockfile` in CI ensures the lock file is in sync with package.json. The `prepublishOnly` script ensures a clean build before publishing to npm.

## Publishing Workflow

Publishing is automated via GitHub Actions (`.github/workflows/npm-publish.yml`):

1. Update `version` in `package.json`
2. Commit and push changes
3. Create and push a git tag: `git tag v0.x.x && git push origin v0.x.x`
4. GitHub Actions runs:
   - `yarn install --frozen-lockfile`
   - `yarn prepublishOnly` (clean + build)
   - `npm publish`

## Node.js Version

This project requires **Node.js >= 22** (see `engines` field in `package.json`).

```bash
# Check your Node.js version
node --version

# Use nvm to install the correct version
nvm install 22
nvm use 22
```

## Additional Resources

- [Yarn 1.x Documentation](https://classic.yarnpkg.com/)
- [Yarn CLI Commands](https://classic.yarnpkg.com/en/docs/cli/)
- [npm Semantic Versioning](https://docs.npmjs.com/about-semantic-versioning)
- Project documentation: See `CLAUDE.md` and `CONTRIBUTING.md` for development guidelines
