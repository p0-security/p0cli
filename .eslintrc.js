module.exports = {
  env: {
    browser: false,
    es2021: true,
  },
  // Note that order here matters
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended-requiring-type-checking",
    "plugin:@typescript-eslint/recommended",
    "prettier",
  ],
  plugins: ["notice"],
  rules: {
    // Allow empty generators
    "require-yield": "off",
    // Assume variables prefixed with "_" are intentionally unused
    "@typescript-eslint/no-unused-vars": [
      "warn",
      { argsIgnorePattern: "_.*", varsIgnorePattern: "_.*" },
    ],
    // Explicit any should be used judiciously to avoid undue wrestling with TS
    "@typescript-eslint/no-explicit-any": "off",
    // no-empty-function is just pedantic
    "@typescript-eslint/no-empty-function": "off",
    // TODO: fix these in the future (all variations of using `any`)
    "@typescript-eslint/no-unsafe-argument": "off",
    "@typescript-eslint/no-unsafe-assignment": "off",
    "@typescript-eslint/no-unsafe-call": "off",
    "@typescript-eslint/no-unsafe-member-access": "off",
    "@typescript-eslint/no-unsafe-return": "off",
    // We may want to improve namespaces at some point, but at this juncture they make
    // our type system more readable
    "@typescript-eslint/no-namespace": "off",
    // This is just so we don't accidentally render '[object: Object]'
    "@typescript-eslint/restrict-template-expressions": [
      "warn",
      { allowNumber: true, allowNullish: true, allowBoolean: true },
    ],
    // This prevents trivial implementations of asynchronous interfaces
    "@typescript-eslint/require-await": "off",
    // For code readability; do not apply to intersections as then order matters
    "@typescript-eslint/sort-type-constituents": [
      "warn",
      { checkIntersections: false },
    ],
    "@typescript-eslint/unbound-method": ["error", { ignoreStatic: true }],
    // Use `print1` and `print2` instead
    "no-console": "error",
    "notice/notice": [
      "error",
      {
        templateFile: "copyright.js",
      },
    ],
  },
  ignorePatterns: [
    ".eslintrc.js",
    "prettier.config.js",
    "vitest.config.mts",
    "public/**",
    "build/**",
    "**/__mocks__/**",
    "**/__tests__/**",
    "node_modules/**",
    "esbuild.js",
    "win",
    "mac",
    "preprocess-sea.cjs",
    "linux",
  ],
  overrides: [],
  parserOptions: {
    ecmaVersion: "latest",
    project: ["./tsconfig.json"],
    sourceType: "module",
  },
};
