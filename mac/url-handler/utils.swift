import Foundation

// Utility functions for P0 URL Handler
// This file contains reusable utilities for URL parsing, shell escaping, and command building
// These functions can be imported into both the main app target and the test target

// MARK: - URL Parsing

/// Parses a p0:// URL into an array of CLI arguments.
/// Converts URL components (host, path, query params) into CLI format,
/// e.g., p0://command/resource?param=value becomes ["command", "resource", "--param=value"].
///
/// - Parameter url: The URL to parse (must have scheme "p0")
/// - Returns: An array of CLI arguments, or nil if the URL is invalid
func parseURL(_ url: URL) -> [String]? {
    // URL format: p0://command/resource?param1=value1&param2=value2
    // Should translate to: p0 command resource --param1=value1 --param2=value2

    guard url.scheme == "p0" else {
        return nil
    }

    var arguments: [String] = []

    // Extract command (host in p0:// URLs)
    if let host = url.host, !host.isEmpty {
        arguments.append(host)
    }

    // Extract path components (resource identifiers)
    let pathComponents = url.pathComponents.filter { $0 != "/" }
    arguments.append(contentsOf: pathComponents)

    // Extract query parameters and convert to CLI flags
    if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
       let queryItems = components.queryItems {
        for item in queryItems {
            if let value = item.value {
                arguments.append("--\(item.name)=\(value)")
            } else {
                arguments.append("--\(item.name)")
            }
        }
    }

    return arguments
}

// MARK: - Shell Command Building

/// Builds a complete shell command with properly escaped arguments.
/// Uses the p0 CLI path and escapes all arguments for safe shell execution.
///
/// - Parameter arguments: The CLI arguments to pass to the p0 command
/// - Returns: A fully-escaped shell command string
func buildShellCommand(_ arguments: [String]) -> String {
    let p0Path = "/usr/local/bin/p0"
    let escapedPath = shellEscape(p0Path)
    let escapedArgs = arguments.map { shellEscape($0) }.joined(separator: " ")
    return "\(escapedPath) \(escapedArgs)"
}

// MARK: - Security-Critical String Escaping

/// Escapes a string for safe use in shell commands by wrapping it in single quotes
/// and escaping any single quotes within using the '\'' pattern.
///
/// Example: `shellEscape("user's-file") // Returns: 'user'\''s-file'`
///
/// - Parameter string: The string to escape
/// - Returns: A shell-safe escaped string wrapped in single quotes
func shellEscape(_ string: String) -> String {
    return "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// Escapes a string for safe use in AppleScript string literals by escaping
/// backslashes and double quotes.
///
/// Example: `applescriptEscape("say \"hello\"") // Returns: say \"hello\"`
///
/// - Parameter string: The string to escape
/// - Returns: An AppleScript-safe escaped string (to be wrapped in double quotes)
func applescriptEscape(_ string: String) -> String {
    return string
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
}
