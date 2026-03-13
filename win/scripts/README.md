## "Run with user as P0" context menu

Scripts in this directory can be used to add a context menu in Windows. When selected, it prompts for a user and reason, then makes a request to the P0 backend. Once approved, the command is run as that user.

### Installation

Installing on a remote windows server:

1. Install p0 for all users (via .msi)
   a. Alternatively
   i. Install node for all users (https://nodejs.org/dist/v24.14.1/node-v24.14.1-x64.msi)
   ii. `mkdir C:\ProgramData\npm`
   iii. `npm config --global set prefix "C:\ProgramData\npm"`
   iv. `setx /M Path "%Path%;C:\ProgramData\npm"`
   v. `npm install -g @p0security/cli`
2. Install gcloud for all users (https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe)
3. Create "C:\ProgramData\P0"
4. Copy the contents of this directory into it
5. Copy https://p0.app/favicon.ico into the directory as p0.ico
6. Theoretically the "Install-P0ContextMenu.ps1" script should set up the context menu; however, it currently hangs on registry edits; instead, manually add these registry keys / values:

```
HKEY_CLASSES_ROOT
  *
    shell
      P0RunAs
        (Default) | Run as user with P0
        Icon | C:\ProgramData\P0\p0.ico
        command
          (Default) - powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\ProgramData\P0\Start-P0RunAs.ps1" -Org {org} -Domain {domain} -Command "%1"
```

7. Run `Register-P0RdpLogout.ps1`
8. Validate context menu
   a. Open up context menu on cmd.exe or PowerShell.exe
   b. Select "Run with user as P0"
   c. Enter a valid user in the domain and a reason
   i. You can get a user by logging in to the P0 CLI and running `p0 ls windows account account --domain {domain}`
   d. Log in to P0
   e. Approve request
   f. Log in to gcloud
   g. In opened shell, run `whoami`
   h. Revoke request
9. Validate logout
   a. Sign out
   b. Reconnect
   c. Ensure that `p0 ls rdp` emits a "not logged in" warning
   d. Ensure that `gcloud auth list` shows no accounts
