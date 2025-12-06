import Cocoa

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

    /// Initializes the AppDelegate and logs the initialization event
    override init() {
        super.init()
        writeLog("===== AppDelegate init =====")
    }

    /// Called when the application finishes launching. Registers the URL event handler and
    /// runs a default command if no URL is received within the timeout period.
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        writeLog("App launched, registering URL event handler")
        // Register for URL events
        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleGetURLEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(kInternetEventClass),
            andEventID: AEEventID(kAEGetURL)
        )
        writeLog("URL event handler registered successfully")

        // When launched via a URL (e.g., clicking p0://ssh/host in a browser), macOS delivers
        // the URL event shortly after applicationDidFinishLaunching completes. We wait for the
        // timeout period to allow the URL event to arrive. If no URL is received by then, this
        // was likely a direct app launch, so we run a default action instead.
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.urlEventTimeout) { [weak self] in
            guard let self = self else { return }
            if !self.urlReceived {
                writeLog("No URL received, running default action: p0 --version")
                self.executeCommand(["--version"])
            }
        }
    }

    /// Called when the application is about to terminate. Placeholder for any cleanup operations.
    func applicationWillTerminate(_ aNotification: Notification) {
        // Cleanup if needed
    }

    /// Indicates whether the application supports secure state restoration (required for macOS 12+).
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }

    /// Handles URL events received via Apple Events (the primary method for custom URL scheme handling).
    /// Extracts the URL from the event descriptor and passes it to handleURL for processing.
    @objc func handleGetURLEvent(_ event: NSAppleEventDescriptor, withReplyEvent replyEvent: NSAppleEventDescriptor) {
        urlReceived = true
        guard let urlString = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              let url = URL(string: urlString) else {
            showError("Invalid URL received")
            NSApplication.shared.terminate(nil)
            return
        }

        handleURL(url)
    }

    /// Alternative URL handler method called when URLs are opened via the application.
    /// Takes the first URL from the array and passes it to handleURL for processing.
    func application(_ application: NSApplication, open urls: [URL]) {
        urlReceived = true
        guard let url = urls.first else {
            showError("No URL provided")
            NSApplication.shared.terminate(nil)
            return
        }

        handleURL(url)
    }

    /// Processes a received URL by parsing it into CLI arguments and executing the corresponding p0 command.
    /// Logs the URL and displays an error if parsing fails.
    private func handleURL(_ url: URL) {
        writeLog("Received URL: \(url.absoluteString)")
        NSLog("p0: Received URL: \(url.absoluteString)")

        // Parse the URL into CLI arguments
        guard let command = parseURL(url) else {
            writeLog("Failed to parse URL")
            NSLog("p0: Failed to parse URL")
            showError("Failed to parse URL: \(url.absoluteString)")
            NSApplication.shared.terminate(nil)
            return
        }

        writeLog("Parsed arguments: \(command)")
        NSLog("p0: Parsed arguments: \(command)")

        // Execute the p0 CLI command
        executeCommand(command)
    }

    /// Writes a timestamped log message to /tmp/p0.log for debugging purposes.
    /// Creates the log file if it doesn't exist, or appends to it if it does.
    private func writeLog(_ message: String) {
        let logPath = "/tmp/p0.log"
        let timestamp = Date()
        let logMessage = "[\(timestamp)] \(message)\n"
        if let data = logMessage.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logPath) {
                if let fileHandle = try? FileHandle(forWritingAtPath: logPath) {
                    fileHandle.seekToEndOfFile()
                    fileHandle.write(data)
                    try? fileHandle.close()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: logPath), options: .atomic)
            }
        }
    }


    /// Executes the p0 CLI command with the given arguments in a new Terminal window.
    /// Verifies the CLI exists, escapes arguments for shell execution, and uses AppleScript to launch Terminal.
    /// This is the primary business logic of the URL handler.
    private func executeCommand(_ arguments: [String]) {
        // P0 CLI should be installed at /usr/local/bin/p0
        let p0Path = "/usr/local/bin/p0"

        writeLog("Checking for CLI at: \(p0Path)")
        NSLog("p0: Checking for CLI at: \(p0Path)")

        guard FileManager.default.fileExists(atPath: p0Path) else {
            writeLog("CLI not found at \(p0Path)")
            NSLog("p0: CLI not found at \(p0Path)")
            showError("P0 CLI not found at \(p0Path).\n\nPlease ensure the P0 CLI is properly installed.")
            NSApplication.shared.terminate(nil)
            return
        }

        writeLog("CLI found, launching Terminal")
        NSLog("p0: CLI found, launching Terminal")

        // Activate the app to ensure permission prompts can be shown
        NSApp.activate(ignoringOtherApps: true)

        // Build the shell command with properly escaped arguments
        let shellCommand = buildShellCommand(arguments)

        // Escape the shell command for AppleScript
        let applescriptEscaped = applescriptEscape(shellCommand)

        // Launch the CLI in a new Terminal window
        let script = """
        tell application "Terminal"
            activate
            do script "\(applescriptEscaped)"
        end tell
        """

        writeLog("AppleScript: \(script)")
        NSLog("p0: AppleScript: \(script)")

        if let appleScript = NSAppleScript(source: script) {
            var error: NSDictionary?
            appleScript.executeAndReturnError(&error)

            if let error = error {
                writeLog("AppleScript error: \(error)")
                NSLog("p0: AppleScript error: \(error)")

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
                writeLog("Successfully launched Terminal")
                NSLog("p0: Successfully launched Terminal")
            }
        }

        // Terminate the helper app after launching the command
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            NSApplication.shared.terminate(nil)
        }
    }

    /// Displays an error dialog to the user with the given message.
    /// Also logs the error to the system log for debugging.
    private func showError(_ message: String) {
        NSLog("p0 Error: \(message)")

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
