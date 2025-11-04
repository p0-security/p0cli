' ==============================================================================
' ManageAlias - Manages executable aliases for P0 Security CLI
' ==============================================================================
'
' PURPOSE:
'   Provides functions to create, update, and remove executable aliases for the
'   P0 CLI. This allows users to install the CLI with a custom executable name
'   (e.g., "stas.exe") while keeping the default "p0.exe" available.
'
'   Uses hardlinks to create aliases, ensuring both names work without
'   duplicating disk space. Falls back to file copy if hardlinks fail.
'
' USAGE CONTEXT:
'   - Called by Windows Installer deferred custom actions
'   - CreateAlias: Runs during installation and upgrades
'   - RemoveAlias: Runs during uninstallation
'
' COMMAND LINE EXAMPLES:
'   msiexec /i installer.msi EXENAME=mycli
'     → Creates hardlink: mycli.exe → p0.exe
'
'   msiexec /i installer.msi
'     → No alias created, only p0.exe exists
'
' REGISTRY TRACKING:
'   HKLM\Software\P0 Security\P0 CLI\InstalledExeName
'     → Stores the current EXENAME for upgrade scenarios
'
' ==============================================================================

Option Explicit

' Registry constants
Const HKEY_LOCAL_MACHINE = &H80000002
Const REG_KEY_PATH = "Software\P0 Security\P0 CLI"
Const REG_VALUE_NAME = "InstalledExeName"

' ==============================================================================
' CreateAlias - Creates or updates executable alias
' ==============================================================================
'
' This function:
'   1. Reads the previous EXENAME from registry (if exists)
'   2. Removes the old alias file if EXENAME changed
'   3. Creates a new hardlink from [EXENAME].exe to p0.exe
'   4. Stores the new EXENAME in registry for future upgrades
'
' RETURN VALUES:
'   1 = Success (or no alias needed)
'   0 = Failure (will cause installation to rollback)
'
' ==============================================================================
Function CreateAlias()
    On Error Resume Next

    ' --------------------------------------------------------------------------
    ' STEP 1: Parse CustomActionData
    ' --------------------------------------------------------------------------
    Dim dict
    Set dict = ParseCustomActionData(Session.Property("CustomActionData"))

    If dict Is Nothing Then
        CreateAlias = 1
        Exit Function
    End If

    Dim installFolder, exeName
    installFolder = dict("INSTALLFOLDER")
    exeName = dict("EXENAME")

    ' Validate required parameters
    If Len(installFolder) = 0 Or Len(exeName) = 0 Then
        CreateAlias = 1
        Exit Function
    End If

    ' Ensure installFolder ends with backslash
    If Right(installFolder, 1) <> "\" Then
        installFolder = installFolder & "\"
    End If

    ' --------------------------------------------------------------------------
    ' STEP 2: Read previous EXENAME from registry
    ' --------------------------------------------------------------------------
    Dim previousExeName
    previousExeName = ReadRegistryValue(REG_KEY_PATH, REG_VALUE_NAME)

    ' If no previous value, assume "p0" (fresh install scenario)
    If Len(previousExeName) = 0 Then
        previousExeName = "p0"
    End If

    ' --------------------------------------------------------------------------
    ' STEP 3: Remove old alias if EXENAME changed
    ' --------------------------------------------------------------------------
    If previousExeName <> exeName And previousExeName <> "p0" Then
        Dim fso
        Set fso = CreateObject("Scripting.FileSystemObject")

        Dim oldAliasPath
        oldAliasPath = installFolder & previousExeName & ".exe"

        ' Delete old alias file if it exists
        If fso.FileExists(oldAliasPath) Then
            fso.DeleteFile oldAliasPath, True
            ' Check for deletion errors (non-critical, continue anyway)
            Err.Clear
        End If
    End If

    ' --------------------------------------------------------------------------
    ' STEP 4: Create new alias (if not "p0")
    ' --------------------------------------------------------------------------
    If exeName <> "p0" Then
        Dim sourcePath, aliasPath
        sourcePath = installFolder & "p0.exe"
        aliasPath = installFolder & exeName & ".exe"

        ' Verify source file exists
        If Not fso.FileExists(sourcePath) Then
            ' Source file missing - this is a critical error
            CreateAlias = 0
            Exit Function
        End If

        ' Create hardlink to the alias
        If Not CreateHardlink(aliasPath, sourcePath) Then
            ' Hardlink creation failed - this is a critical error
            CreateAlias = 0
            Exit Function
        End If
    End If

    ' --------------------------------------------------------------------------
    ' STEP 5: Store current EXENAME in registry
    ' --------------------------------------------------------------------------
    If Not WriteRegistryValue(REG_KEY_PATH, REG_VALUE_NAME, exeName) Then
        ' Registry write failed - log but don't fail installation
        ' The alias was created successfully, so we can continue
        Err.Clear
    End If

    ' Success
    CreateAlias = 1
End Function

' ==============================================================================
' RemoveAlias - Removes executable alias during uninstallation
' ==============================================================================
'
' This function:
'   1. Reads the EXENAME from registry
'   2. Deletes the alias file (if not "p0")
'   3. Does NOT delete registry (handled by RegistryComponent removal)
'
' RETURN VALUES:
'   1 = Success (or no alias to remove)
'   0 = Failure (but Return="ignore" in WiX prevents rollback)
'
' ==============================================================================
Function RemoveAlias()
    On Error Resume Next

    ' --------------------------------------------------------------------------
    ' STEP 1: Parse CustomActionData
    ' --------------------------------------------------------------------------
    Dim dict
    Set dict = ParseCustomActionData(Session.Property("CustomActionData"))

    If dict Is Nothing Then
        RemoveAlias = 1
        Exit Function
    End If

    Dim installFolder
    installFolder = dict("INSTALLFOLDER")

    ' Validate required parameters
    If Len(installFolder) = 0 Then
        RemoveAlias = 1
        Exit Function
    End If

    ' Ensure installFolder ends with backslash
    If Right(installFolder, 1) <> "\" Then
        installFolder = installFolder & "\"
    End If

    ' --------------------------------------------------------------------------
    ' STEP 2: Read EXENAME from registry
    ' --------------------------------------------------------------------------
    Dim exeName
    exeName = ReadRegistryValue(REG_KEY_PATH, REG_VALUE_NAME)

    ' If no registry value or value is "p0", nothing to remove
    If Len(exeName) = 0 Or exeName = "p0" Then
        RemoveAlias = 1
        Exit Function
    End If

    ' --------------------------------------------------------------------------
    ' STEP 3: Delete alias file
    ' --------------------------------------------------------------------------
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")

    Dim aliasPath
    aliasPath = installFolder & exeName & ".exe"

    If fso.FileExists(aliasPath) Then
        fso.DeleteFile aliasPath, True

        ' Check for errors (non-critical during uninstall)
        If Err.Number <> 0 Then
            Err.Clear
            ' Continue anyway - best effort cleanup
        End If
    End If

    ' Success (or best effort)
    RemoveAlias = 1
End Function

' ==============================================================================
' HELPER FUNCTIONS
' ==============================================================================

' ------------------------------------------------------------------------------
' ParseCustomActionData - Parses CustomActionData string into dictionary
' ------------------------------------------------------------------------------
'
' CustomActionData format: "KEY1=VALUE1;KEY2=VALUE2;..."
' Returns: Dictionary object with key-value pairs, or Nothing on error
'
Function ParseCustomActionData(data)
    On Error Resume Next

    Dim dict
    Set dict = CreateObject("Scripting.Dictionary")

    If Len(data) = 0 Then
        Set ParseCustomActionData = Nothing
        Exit Function
    End If

    Dim pairs, pair, keyValue
    pairs = Split(data, ";")

    For Each pair In pairs
        keyValue = Split(pair, "=")
        If UBound(keyValue) = 1 Then
            dict(keyValue(0)) = keyValue(1)
        End If
    Next

    Set ParseCustomActionData = dict
End Function

' ------------------------------------------------------------------------------
' CreateHardlink - Creates a hardlink with fallback to file copy
' ------------------------------------------------------------------------------
'
' Parameters:
'   linkPath - Path for the new hardlink (alias)
'   targetPath - Path to the existing file (p0.exe)
'
' Returns: True on success, False on failure
'
Function CreateHardlink(linkPath, targetPath)
    On Error Resume Next

    Dim shell, cmd, result
    Set shell = CreateObject("WScript.Shell")

    ' --------------------------------------------------------------------------
    ' Attempt 1: Create hardlink using fsutil
    ' --------------------------------------------------------------------------
    ' Hardlinks are preferred because:
    '   - No disk space duplication
    '   - Both files are identical (same inode)
    '   - Updates to one automatically update the other

    cmd = "fsutil hardlink create """ & linkPath & """ """ & targetPath & """"
    result = shell.Run(cmd, 0, True)

    ' Check if hardlink creation succeeded
    If result = 0 And Err.Number = 0 Then
        CreateHardlink = True
        Exit Function
    End If

    ' Clear any errors from hardlink attempt
    Err.Clear

    ' --------------------------------------------------------------------------
    ' Attempt 2: Fallback to file copy
    ' --------------------------------------------------------------------------
    ' Hardlinks can fail if:
    '   - Files are on different volumes
    '   - File system doesn't support hardlinks (non-NTFS)
    '   - Insufficient permissions

    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")

    ' Remove existing file if it exists (copy won't overwrite)
    If fso.FileExists(linkPath) Then
        fso.DeleteFile linkPath, True
        If Err.Number <> 0 Then
            CreateHardlink = False
            Exit Function
        End If
    End If

    ' Perform file copy
    fso.CopyFile targetPath, linkPath, True

    ' Check if copy succeeded
    If Err.Number <> 0 Then
        CreateHardlink = False
        Exit Function
    End If

    CreateHardlink = True
End Function

' ------------------------------------------------------------------------------
' ReadRegistryValue - Reads a string value from the registry
' ------------------------------------------------------------------------------
'
' Parameters:
'   keyPath - Registry key path (e.g., "Software\P0 Security\P0 CLI")
'   valueName - Name of the value to read
'
' Returns: String value, or empty string if not found
'
Function ReadRegistryValue(keyPath, valueName)
    On Error Resume Next

    Dim registry, value
    Set registry = GetObject("winmgmts://./root/default:StdRegProv")

    ' Attempt to read the value
    registry.GetStringValue HKEY_LOCAL_MACHINE, keyPath, valueName, value

    ' Check if read succeeded
    If Err.Number <> 0 Or IsNull(value) Then
        ReadRegistryValue = ""
        Err.Clear
        Exit Function
    End If

    ReadRegistryValue = value
End Function

' ------------------------------------------------------------------------------
' WriteRegistryValue - Writes a string value to the registry
' ------------------------------------------------------------------------------
'
' Parameters:
'   keyPath - Registry key path (e.g., "Software\P0 Security\P0 CLI")
'   valueName - Name of the value to write
'   value - String value to write
'
' Returns: True on success, False on failure
'
Function WriteRegistryValue(keyPath, valueName, value)
    On Error Resume Next

    Dim registry
    Set registry = GetObject("winmgmts://./root/default:StdRegProv")

    ' Create the key if it doesn't exist
    registry.CreateKey HKEY_LOCAL_MACHINE, keyPath
    If Err.Number <> 0 Then
        WriteRegistryValue = False
        Exit Function
    End If

    ' Write the value
    registry.SetStringValue HKEY_LOCAL_MACHINE, keyPath, valueName, value

    ' Check if write succeeded
    If Err.Number <> 0 Then
        WriteRegistryValue = False
        Exit Function
    End If

    WriteRegistryValue = True
End Function
