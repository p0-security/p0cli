' ==============================================================================
' RenameExecutable - Renames the installed p0.exe to a custom executable name
' ==============================================================================
'
' PURPOSE:
'   This function is called by a Windows Installer deferred custom action during
'   installation. It renames the installed p0.exe file to a user-specified name
'   if the EXENAME parameter was provided via msiexec command line.
'
' USAGE CONTEXT:
'   - Called automatically during MSI installation
'   - Runs AFTER files are copied (scheduled After="InstallFiles")
'   - Runs with elevated/admin privileges (Impersonate="no")
'
' COMMAND LINE EXAMPLES:
'   msiexec /i installer.msi EXENAME=mycli
'     → Renames p0.exe to mycli.exe
'
'   msiexec /i installer.msi
'     → Keeps default name p0.exe (no rename)
'
' RETURN VALUES:
'   1 = Success (or no rename needed)
'   0 = Failure (will cause installation to rollback)
'
' ==============================================================================

Function RenameExecutable()
    ' Enable error handling: Continue execution even if errors occur
    ' We'll check for errors manually after critical operations
    On Error Resume Next

    ' --------------------------------------------------------------------------
    ' STEP 1: Parse CustomActionData to extract properties
    ' --------------------------------------------------------------------------
    ' Deferred custom actions cannot directly access installer properties like
    ' [INSTALLFOLDER] or [EXENAME]. Instead, an immediate custom action
    ' (SetRenameExeData) packages these values into a special property called
    ' CustomActionData as a string like: "INSTALLFOLDER=C:\Program Files\p0;EXENAME=mycli"
    '
    ' We need to parse this string to extract the individual values.

    Dim data, pairs, pair, dict

    ' Create a Dictionary object to store key-value pairs
    Set dict = CreateObject("Scripting.Dictionary")

    ' Retrieve the CustomActionData string passed from the immediate action
    ' Example value: "INSTALLFOLDER=C:\Program Files\p0\;EXENAME=mycli"
    data = Session.Property("CustomActionData")

    ' Split the string by semicolons to get individual key=value pairs
    ' Result: pairs(0) = "INSTALLFOLDER=C:\Program Files\p0\", pairs(1) = "EXENAME=mycli"
    pairs = Split(data, ";")

    ' Loop through each key=value pair and add to dictionary
    For Each pair In pairs
        Dim keyValue
        ' Split each pair by "=" to separate key from value
        ' Example: "EXENAME=mycli" becomes keyValue(0)="EXENAME", keyValue(1)="mycli"
        keyValue = Split(pair, "=")

        ' UBound returns the highest index (1 means we have exactly 2 elements: key and value)
        ' This check ensures the pair was formatted correctly
        If UBound(keyValue) = 1 Then
            ' Add to dictionary: dict("EXENAME") = "mycli"
            dict(keyValue(0)) = keyValue(1)
        End If
    Next

    ' --------------------------------------------------------------------------
    ' STEP 2: Extract the values we need from the dictionary
    ' --------------------------------------------------------------------------

    Dim installFolder, exeName, fso
    ' Get the installation directory (e.g., "C:\Program Files\p0\")
    installFolder = dict("INSTALLFOLDER")
    ' Get the desired executable name (e.g., "mycli")
    exeName = dict("EXENAME")

    ' --------------------------------------------------------------------------
    ' STEP 3: Validate that we have the required data
    ' --------------------------------------------------------------------------

    ' Check if either value is empty/missing
    ' Len() returns the length of a string (0 means empty)
    If Len(installFolder) = 0 Or Len(exeName) = 0 Then
        ' Missing required data, but this shouldn't fail the installation
        ' Return success (1) and exit early to keep the default name
        RenameExecutable = 1
        Exit Function
    End If

    ' --------------------------------------------------------------------------
    ' STEP 4: Prepare to perform file operations
    ' --------------------------------------------------------------------------

    ' Create a FileSystemObject to interact with the file system
    ' This provides methods like MoveFile, FileExists, etc.
    Set fso = CreateObject("Scripting.FileSystemObject")

    ' --------------------------------------------------------------------------
    ' STEP 5: Build the full file paths
    ' --------------------------------------------------------------------------

    Dim oldPath, newPath
    ' Construct the path to the currently installed file
    ' Example: "C:\Program Files\p0\p0.exe"
    oldPath = installFolder & "p0.exe"

    ' Construct the path for the renamed file
    ' Example: "C:\Program Files\p0\mycli.exe"
    newPath = installFolder & exeName & ".exe"

    ' --------------------------------------------------------------------------
    ' STEP 6: Rename the file if needed
    ' --------------------------------------------------------------------------

    ' Check if the source file exists before trying to rename it
    If fso.FileExists(oldPath) Then
        ' Only rename if the new name is different from the default
        ' If user specified EXENAME=p0, there's no need to rename
        If exeName <> "p0" Then
            ' Perform the rename operation
            ' MoveFile effectively renames the file (moves it to the same directory with new name)
            fso.MoveFile oldPath, newPath

            ' Check if an error occurred during the move operation
            ' Err.Number = 0 means success, any other value means an error occurred
            If Err.Number <> 0 Then
                ' Rename failed - return failure code (0)
                ' This will cause the installation to rollback
                RenameExecutable = 0
                Exit Function
            End If
        End If
    End If

    ' --------------------------------------------------------------------------
    ' STEP 7: Return success
    ' --------------------------------------------------------------------------

    ' Return 1 to indicate success
    ' The installation will continue normally
    RenameExecutable = 1
End Function
