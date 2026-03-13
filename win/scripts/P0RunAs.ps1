<#
  .SYNOPSIS
      Authenticates with P0 Security, retrieves a GCP secret via delegation, and runs a command as Administrator.

  .PARAMETER Org
      The P0 org identifier (e.g. "my-company").

  .PARAMETER Reason
      The reason this access is needed.

  .PARAMETER Command
      The executable to run as Administrator using the retrieved secret as the password.

  .PARAMETER Arguments
      Arguments to pass to the command. Use this instead of embedding arguments in
      -Command so that paths containing spaces are handled correctly.

  .PARAMETER Domain
      The directory domain in which the user resides. Defaults to ".".

  .PARAMETER User
      The username to run the command as. Defaults to "localadmin".

  .EXAMPLE
      .\P0RunAs.ps1 -Org "my-company" -Command "whoami" -Reason "update data upload interval"

  .EXAMPLE
      .\P0RunAs.ps1 -Org "my-company" -Command "C:\Program Files\MyApp\app.exe" -Arguments "--flag value" -Reason "run app"
  #>

  param(
      [Parameter(Mandatory)][string]$Org,
      [Parameter(Mandatory)][string]$Command,
      [Parameter(Mandatory)][string]$Reason,
      [string]$Arguments = "",
      [string]$Domain = ".",
      [string]$User = "localadmin"
  )

  Set-StrictMode -Version Latest
  $ErrorActionPreference = "Stop"

  # ---------------------------------------------------------------------------
  # Step 1: Log in to P0
  # ---------------------------------------------------------------------------
  Write-Host "Logging in to P0 organization '$Org'..." -ForegroundColor Cyan
  p0 login $Org
  if ($LASTEXITCODE -ne 0) { throw "p0 login failed (exit code $LASTEXITCODE)" }

  # ---------------------------------------------------------------------------
  # Step 2: Request an SSH session and parse the request ID
  # ---------------------------------------------------------------------------
  Write-Host "Requesting credentials for '$Domain\$User'..." -ForegroundColor Cyan
  $ErrorActionPreference = 'Continue'
  $requestSuccessful = $false
  $attemptsLeft = 2
  while (!$requestSuccessful -and $attemptsLeft -gt 0) {
    p0 request --wait windows account $Domain $User --reason $Reason 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -Variable P0Output
    if ($LASTEXITCODE -eq 0) {
      $requestSuccessful = $true
    } else {
      $attemptsLeft--
      Write-Host "Will retry ($attemptsLeft tries remaining)"
    }
  }
  if (!$requestSuccessful) { 
    exit(1)
  }
  $ErrorActionPreference = 'Stop'

  # P0 CLI emits: "Access requested (see https://demo.p0.app/o/<tenant>/access-management/activity/<request_id> for details)"
  $requestId = $null
  $Matches = $null
  ForEach ($Line in $P0Output.split("`r`n")) {
    if ($Line -match '/access-management/activity/([a-zA-Z0-9_\-]+)') {
      $requestId = $Matches[1]
    }
  }
  if (!$requestId) {
    throw "No request ID found in output"
  }
  Write-Host "Request ID: $requestId" -ForegroundColor Green

  # ---------------------------------------------------------------------------
  # Step 3: Extract the access token
  # ---------------------------------------------------------------------------
  $accessToken = p0 print-bearer-token
  if ([string]::IsNullOrEmpty($accessToken)) {
      throw "access_token not found in identity.json"
  }

  # ---------------------------------------------------------------------------
  # Step 4: Fetch the permission-request object from P0
  # ---------------------------------------------------------------------------
  $requestUrl = "https://api.demo.p0.app/o/$Org/permission-requests/$requestId"
  Write-Host "Fetching request object from $requestUrl ..." -ForegroundColor Cyan
  $headers = @{ Authorization = "Bearer $accessToken" }
  $requestObj = Invoke-RestMethod -Uri $requestUrl -Headers $headers -Method Get

  # ---------------------------------------------------------------------------
  # Step 5: Extract delegation.gsm-static.locator
  # ---------------------------------------------------------------------------
  # The property path contains hyphens, so we navigate with PSObject.Properties
  $delegation = $requestObj.delegation
  $gsmStatic  = $delegation.PSObject.Properties['gsm-static'].Value.permission
  $name       = $gsmStatic.locator
  $projectId  = $gsmStatic.projectId

  $locator = "projects/$projectId/secrets/$name"

  if ([string]::IsNullOrEmpty($locator)) {
      throw "delegation.gsm-static.locator is empty or missing in the request object"
  }
  Write-Host "GCP Secret locator: $locator" -ForegroundColor Green

  # ---------------------------------------------------------------------------
  # Step 6: Log in to GCP
  # ---------------------------------------------------------------------------
  try {
    # 2>&1 causes login failure to throw an error
    gcloud auth print-access-token 2>&1 | Out-Null
    Write-Host "Already logged in to GCP"
  } catch {
    Write-Host "Logging in to GCP..." -ForegroundColor Cyan
    gcloud auth login
    if ($LASTEXITCODE -ne 0) { throw "gcloud auth login failed (exit code $LASTEXITCODE)" }
  }

  # ---------------------------------------------------------------------------
  # Step 7: Fetch the latest secret version from Secret Manager
  #
  # The locator is expected to be a full GCP resource path, e.g.:
  #   projects/my-project/secrets/my-secret
  # or already versioned:
  #   projects/my-project/secrets/my-secret/versions/latest
  # ---------------------------------------------------------------------------
  Write-Host "Fetching secret from GCP Secret Manager..." -ForegroundColor Cyan
  $secret = gcloud secrets versions access latest --project=$projectId --secret=$name --format="get(payload.data)" 2>&1
  if ($LASTEXITCODE -ne 0) { throw "gcloud secrets versions access failed (exit code $LASTEXITCODE)`n$secret" }

  # The payload is base64-encoded when fetched via the API; gcloud CLI decodes it automatically.
  # If it arrives as base64, decode it:
  try {
      $decodedBytes = [System.Convert]::FromBase64String($secret.Trim())
      $secret       = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
  } catch {
      # Already plaintext — use as-is
  }

  # ---------------------------------------------------------------------------
  # Step 8: Run the specified command as user
  # ---------------------------------------------------------------------------
  Write-Host "Running command as '$User'..." -ForegroundColor Cyan
  $securePassword = ConvertTo-SecureString $secret -AsPlainText -Force
  $credential     = New-Object System.Management.Automation.PSCredential("$Domain\$User", $securePassword)

  $procParams = @{
      FilePath    = $Command
      Credential  = $credential
      Wait        = $false
      NoNewWindow = $true
  }
  if ($Arguments) { $procParams.ArgumentList = $Arguments }

  # This shell will compete for input with the new terminal (if it's PowerShell)
  Remove-Module PSReadLine
  Start-Process @procParams

  Write-Host "Done." -ForegroundColor Green
  exit(0)