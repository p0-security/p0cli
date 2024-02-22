/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  testRegex: ".*\\.test\\.ts$",
  prettierPath: null,
  preset: "ts-jest",
  testEnvironment: "node",
  modulePathIgnorePatterns: ["/build"],
};
