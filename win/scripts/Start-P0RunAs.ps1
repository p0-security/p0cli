<#
.SYNOPSIS
    Launcher invoked by the "Run with P0..." Explorer context menu entry.
    Prompts the user for P0 parameters, then delegates to p0runas.ps1.

.PARAMETER Command
    Command to run. Passed automatically by Explorer as %1.

.PARAMETER Org
    Optional. If supplied by the installer (baked-in org), the user will not be prompted.
#>

param(
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][string]$Org
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName PresentationFramework

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Run with P0"
        Width="260" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize">
    <StackPanel Margin="10">
        <Label Name="domainLabel" Margin="0,10,0,0"/>
        <TextBox Name="userBox" Margin="0,0,0,10"/>
        <Label Content="Reason access is needed" Margin="0,10,0,0"/>
        <TextBox Name="reasonBox" Margin="0,0,0,10"/>
        <Button Name="okButton" Content="Select" IsDefault="True"
                HorizontalAlignment="Center" Width="80" Margin="0,10,0,10"/>
    </StackPanel>
</Window>
'@

$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$window.FindName('domainLabel').Content = "User in domain $Domain"
$userBox   = $window.FindName('userBox')
$reasonBox = $window.FindName('reasonBox')
$window.FindName('okButton').Add_Click({ $window.DialogResult = $true })

$result = $window.ShowDialog()
if (-not $result -or [string]::IsNullOrWhiteSpace($userBox.Text)) {
    exit 0
}
$User = $userBox.Text
$Reason = $reasonBox.Text

& (Join-Path $PSScriptRoot "P0RunAs.ps1") `
    -Org       $Org `
    -Command   $Command `
    -Domain    $Domain `
    -User      $User `
    -Reason    $Reason