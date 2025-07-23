# Contributing to the P0 CLI

Thank you for your interest in contributing to the P0 CLI!

## CLA

All contributors must first sign P0's contributor license agreement. This ensures
that your contribution is properly licensed under the CLI's open-source license
agreement.

Send an email to support@p0.dev, or submit a PR via a GitHub user with a valid email
address, and we'll hook you up.

## Guidelines

Since this project is a user-consumable command-line interface, we ask that contributions
follow certain guidelines, in order to ensure usability of the CLI:

- All console text not meant to be consumed by a machine should be emmitted via `console.error`
  - Text that will be consumed by a machine, or either a machine or a human, should be emmitted
    via `console.log`
- Client-usage errors (that is, errors that provide feedback to the user of expected CLI misuse)
  should be emmitted using `throw <message>`; this prevents a stack trace from being shown

## Single-Artifact Binary

To build the CLI as a single-artifact binary, use the `yarn build:macos` script and then
run `build.sh`. You must have NodeJS version 22 or newer currently installed on your system
when building the standalone CLI. The resulting binary will be output to `/build/sea`, and can
be run even if NodeJS is uninstalled on your system. Currently only MacOS is supported.
