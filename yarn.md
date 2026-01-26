# Yarn Guide for P0 CLI

This guide covers how to use Yarn for development on the P0 CLI project.

## Prerequisites

This project requires **Node.js >= 22** and uses **Yarn 1.22.22** (Yarn Classic).

```bash
# Check your Node.js version
node --version

# Install the correct Node.js version if needed
nvm install 22
nvm use 22
```

The Yarn version is automatically enforced via the `packageManager` field in `package.json`.

## Quick Start

```bash
# Install dependencies
yarn install

# Build the CLI
yarn build

# Run the CLI locally
yarn p0 --version
yarn p0 --help

# Run tests
yarn test
```

## Common Development Commands

```bash
# Install dependencies
yarn install

# Add a new dependency
yarn add <package-name>

# Add a new devDependency
yarn add -D <package-name>

# Remove a dependency
yarn remove <package-name>

# Build the CLI
yarn build

# Run tests
yarn test

# Run linting
yarn lint

# Format code
yarn format

# Clean build artifacts
yarn clean
```

## Development Workflow

1. Make your changes
2. Run `yarn lint` and `yarn format` to check code style
3. Run `yarn test` to ensure tests pass
4. Run `yarn build` to verify the CLI builds correctly
5. Test your changes with `yarn p0 <command>`

## Dependency Management

### Best Practices

- Use `devDependencies` for build tools, linters, and test frameworks
- Only use `dependencies` for code that ships with the CLI
- Use semantic version ranges (`^1.2.3`) instead of pinning to exact versions
- Run `yarn audit` before committing dependency changes

### Managing Updates

```bash
# Interactive upgrade tool
yarn upgrade-interactive --latest

# Upgrade a specific package
yarn upgrade <package-name>

# Check for security vulnerabilities
yarn audit
```

After upgrading dependencies, always run `yarn lint`, `yarn test`, and `yarn build` to ensure everything works.

## Additional Scripts

For more advanced or project-specific commands, check the `scripts` section in [package.json](package.json). This includes specialized build tasks, testing utilities, and other development tools specific to the P0 CLI project.

## Advanced Usage

### CI/CD Environments

For CI/CD pipelines, use `--frozen-lockfile` to ensure reproducible builds:

```bash
yarn install --frozen-lockfile
```

This prevents lock file updates and fails if the lock file is out of sync with package.json.

## Troubleshooting

### Installation Issues

```bash
# Clear cache and reinstall
yarn cache clean
rm -rf node_modules
yarn install
```

### Lock File Conflicts

When merging branches with lock file conflicts:

```bash
# Accept one side (e.g., main branch)
git checkout main -- yarn.lock

# Regenerate lock file
yarn install

# Commit the resolved lock file
git add yarn.lock
git commit -m "Resolve yarn.lock conflicts"
```

### Platform-Specific Issues

On macOS with Apple Silicon:

```bash
arch -arm64 yarn install
```

For native module rebuilds:

```bash
yarn install --force
```

## Additional Resources

- [Yarn 1.x Documentation](https://classic.yarnpkg.com/)
- [Yarn CLI Commands](https://classic.yarnpkg.com/en/docs/cli/)
- [npm Semantic Versioning](https://docs.npmjs.com/about-semantic-versioning)
