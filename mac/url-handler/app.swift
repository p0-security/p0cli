import Cocoa
import os

@main
struct Main {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    /// Timeout in seconds to wait for a URL event before running the default action
    private static let urlEventTimeout: TimeInterval = 0.5

    private var urlReceived = false

    /// Logger instance for unified logging with proper log levels
    private let logger = Logger(subsystem: "dev.p0.cli.urlhandler", category: "main")

    /// Path to the log file for this specific process invocation
    private lazy var logFilePath: String = {
        let pid = ProcessInfo.processInfo.processIdentifier
        return "/tmp/p0-\(pid).log"
    }()

    /// Initializes the AppDelegate and logs the initialization event
    override init() {
        super.init()
        initLogging()
        log("===== AppDelegate init =====")
    }

    /// Called when the application is about to terminate. Placeholder for any cleanup operations.
    func applicationWillTerminate(_ aNotification: Notification) {
        // Cleanup if needed
    }

    /// Indicates whether the application supports secure state restoration (required for macOS 12+).
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }

    /// Called when the application finishes launching. Registers the URL event handler and
    /// runs a default command if no URL is received within the timeout period. The URL event handler
    /// is registered with Apple Events. This is the primary mechanism for handling custom URL schemes on macOS
    /// that gets invoked when a user opens a p0:// URL in their web browser.
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        log("App launched, registering URL event handler")
        // Register for URL events
        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleGetURLEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(kInternetEventClass),
            andEventID: AEEventID(kAEGetURL)
        )
        log("URL event handler registered successfully")

        // When launched via a URL (e.g., clicking p0://ssh/host in a browser), macOS delivers
        // the URL event shortly after applicationDidFinishLaunching completes. We wait for the
        // timeout period to allow the URL event to arrive. If no URL is received by then, this
        // was likely a direct app launch, so we run a default action instead.
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.urlEventTimeout) { [weak self] in
            guard let self = self else { return }
            if !self.urlReceived {
                log("No URL received, running default action: p0 --version")
                self.executeCommand(["--version"])
            }
        }
    }


    /// Alternative URL handler method called when URLs are opened via the application.
    /// Takes the first URL from the array and passes it to handleURL for processing. This
    /// method is an alternative entry point to the handler that is registered in
    /// applicationDidFinishLaunching that can sometimes be invoked directly by the system
    /// (e.g., through drag-and-drop or file associations), though this is less common.
    func application(_ application: NSApplication, open urls: [URL]) {
        urlReceived = true
        guard let url = urls.first else {
            showError("No URL provided")
            NSApplication.shared.terminate(nil)
            return
        }

        handleURL(url)
    }

    /// Handles URL events received via Apple Events (the primary method for custom URL scheme handling).
    /// Extracts the URL from the event descriptor and passes it to handleURL for processing.
    @objc func handleGetURLEvent(_ event: NSAppleEventDescriptor, withReplyEvent replyEvent: NSAppleEventDescriptor) {
        urlReceived = true
        let rawInput = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue
        guard let urlString = rawInput, let url = URL(string: urlString) else {
            logError("Invalid URL received: \(rawInput ?? "<none>")")
            showError("Invalid URL received: \(rawInput ?? "<none>")")
            NSApplication.shared.terminate(nil)
            return
        }

        handleURL(url)
    }


    /// Processes a received URL by parsing it into CLI arguments and executing the corresponding p0 command.
    /// Logs the URL and displays an error if parsing fails.
    private func handleURL(_ url: URL) {
        log("Received URL: \(url.absoluteString)")

        // Parse the URL into CLI arguments
        guard let command = parseURL(url) else {
            log("Failed to parse URL: \(url.absoluteString)")
            showError("Failed to parse URL: \(url.absoluteString)")
            NSApplication.shared.terminate(nil)
            return
        }

        log("Parsed arguments: \(command)")

        // Execute the p0 CLI command
        executeCommand(command)
    }

    /// Executes the p0 CLI command with the given arguments in a new Terminal window.
    /// Verifies the CLI exists, escapes arguments for shell execution, and uses AppleScript to launch Terminal.
    /// This is the primary business logic of the URL handler.
    private func executeCommand(_ arguments: [String]) {
        log("Checking for CLI at: \(P0_PATH)")

        guard FileManager.default.fileExists(atPath: P0_PATH) else {
            log("CLI not found at \(P0_PATH)")
            showError("P0 CLI not found at \(P0_PATH).\n\nPlease ensure the P0 CLI is properly installed.")
            NSApplication.shared.terminate(nil)
            return
        }

        log("CLI found, launching Terminal")

        // Activate the app to ensure permission prompts can be shown
        NSApp.activate(ignoringOtherApps: true)

        // Build the AppleScript with properly escaped arguments
        let script = buildApplescript(arguments)

        log("AppleScript:\n\n\(script)\n\n")

        if let appleScript = NSAppleScript(source: script) {
            var error: NSDictionary?
            appleScript.executeAndReturnError(&error)

            if let error = error {
                log("AppleScript error: \(error)")

                // Check if this is a permissions error
                let errorNumber = error["NSAppleScriptErrorNumber"] as? Int
                let errorMessage = error["NSAppleScriptErrorMessage"] as? String ?? ""

                if errorNumber == -1743 || errorMessage.contains("Not authorized") || errorMessage.contains("not allowed") {
                    showError("""
                        P0 needs permission to control Terminal.

                        To grant permission:
                        1. Open System Settings (or System Preferences)
                        2. Go to Privacy & Security → Automation
                        3. Find "p0" in the list
                        4. Enable the checkbox for "Terminal"

                        Then try again.
                        """)
                } else {
                    showError("Failed to execute command: \(errorMessage)")
                }
            } else {
                log("Successfully launched Terminal")
            }
        }

        // Terminate the helper app after launching the command
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            NSApplication.shared.terminate(nil)
        }
    }

    /// Initializes the logging system by clearing any existing log file with the same PID.
    /// This ensures each invocation starts with a clean log file.
    private func initLogging() {
        if FileManager.default.fileExists(atPath: logFilePath) {
            try? FileManager.default.removeItem(atPath: logFilePath)
        }
    }

    /// Logs a message to both the unified logging system and a process-specific log file in /tmp.
    /// Each process invocation gets its own log file at /tmp/p0-{PID}.log for easy debugging.
    private func log(_ message: String) {
        // Log to unified logging system at default level
        logger.log("\(message, privacy: .public)")

        // Also write to process-specific file for easy access
        writeToFile(message)
    }

    /// Logs an error message with appropriate error level in unified logging
    private func logError(_ message: String) {
        // Log to unified logging system at error level
        logger.error("\(message, privacy: .public)")
        writeToFile("Error: \(message)")
    }

    /// Writes a timestamped log message to this process's log file in /tmp.
    /// Creates the log file if it doesn't exist, or appends to it if it does.
    private func writeToFile(_ message: String) {
        let timestamp = Date()
        let logMessage = "[\(timestamp)] \(message)\n"
        if let data = logMessage.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logFilePath) {
                if let fileHandle = try? FileHandle(forWritingTo: URL(fileURLWithPath: logFilePath)) {
                    fileHandle.seekToEndOfFile()
                    fileHandle.write(data)
                    try? fileHandle.close()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: logFilePath), options: .atomic)
            }
        }
    }

    /// Displays an error dialog to the user with the given message.
    /// Also logs the error to the system log for debugging.
    private func showError(_ message: String) {
        logError(message)

        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "P0 URL Handler Error"
            alert.informativeText = message
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}
