<#
.SYNOPSIS
    SeatbeltPS - "Everything" edition with parentheses fixes
    Prints system enumeration to screen, transcripts to .txt, writes JSON.

.DESCRIPTION
    Removes extra parentheses in if-statements (e.g., if (!(Require-Admin "Foo"))) 
    => if (!(Require-Admin "Foo")) to avoid parse errors.

.NOTES
    Author: ChatGPT
    Date:   2025-03-14
#>

function Invoke-SeatbeltPS {
    [CmdletBinding()]
    param(
        [string]$OutputFile = "SeatbeltPS_Report_$(Get-Date -Format yyyyMMddHHmmss).json",
        [string]$TextOutputFile = "SeatbeltPS_Output_$(Get-Date -Format yyyyMMddHHmmss).txt"
    )

    #region [Helper Functions]
    function Get-RegistryValue {
        param(
            [string]$Path,
            [string]$Name
        )
        try {
            (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        }
        catch {
            $null
        }
    }

    function Get-IdleTime {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class IdleTime {
    [DllImport("user32.dll")]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    public struct LASTINPUTINFO {
        public uint cbSize;
        public uint dwTime;
    }
    public static uint Get() {
        LASTINPUTINFO lii = new LASTINPUTINFO();
        lii.cbSize = (uint)Marshal.SizeOf(lii);
        GetLastInputInfo(ref lii);
        return (uint)Environment.TickCount - lii.dwTime;
    }
}
"@ -ErrorAction SilentlyContinue

        try {
            return [IdleTime]::Get()
        }
        catch {
            return $null
        }
    }

    function Require-Admin([string]$CmdName) {
        if (-not $IsAdmin) {
            Write-Warning "[$CmdName] requires Administrator privileges. Skipping."
            return $true
        }
        return $false
    }
    #endregion

    #region [Check Elevation + Start Transcript]
    # Single-line cast to avoid parse errors
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    try {
        Start-Transcript -Path $TextOutputFile -Append | Out-Null
    }
    catch {
        Write-Host "[!] Could not start transcript. Error: $_"
    }
    #endregion

    #region [Master Report Object]
    $report = [ordered]@{
        Metadata = [ordered]@{
            Timestamp = (Get-Date).ToString("o")
            Hostname  = $env:COMPUTERNAME
            User      = "$env:USERDOMAIN\$env:USERNAME"
            Elevated  = $IsAdmin
            OSVersion = [Environment]::OSVersion.Version
        }
    }

    Write-Host "=================================================="
    Write-Host "  SeatbeltPS (Everything Edition - Parentheses Fixed)"
    Write-Host "  Host: $($report.Metadata.Hostname), User: $($report.Metadata.User), Elevated: $($report.Metadata.Elevated)"
    Write-Host "  Transcript => $TextOutputFile"
    Write-Host "  JSON => $OutputFile"
    Write-Host "==================================================`n"
    #endregion

    #region [SYSTEM]
    Write-Host "=== [SYSTEM INFORMATION] ==="
    $system = [ordered]@{}

    Write-Host "`n--- OS/Computer Info ---"
    try {
        $sysInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture, OsBuildNumber
        $system.ComputerInfo = $sysInfo
        $sysInfo | Out-Host
    } catch {}

    Write-Host "`n--- .NET Versions ---"
    try {
        $dotNet = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse -ErrorAction SilentlyContinue |
                  Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
                  Where-Object { $_.PSChildName -match "^(?!S)\p{L}*" -or $_.Version -match "^\d" } |
                  Select-Object PSChildName, Version, Release
        $system.DotNetVersions = $dotNet
        $dotNet | Out-Host
    } catch {}

    Write-Host "`n--- Idle Time (ms) ---"
    $idleMs = Get-IdleTime
    $system.IdleTime = $idleMs
    Write-Host $idleMs

    Write-Host "`n--- Hotfixes ---"
    try {
        $hfs = Get-HotFix | Select-Object HotFixID, Description, InstalledOn
        $system.Hotfixes = $hfs
        $hfs | Out-Host
    } catch {}

    Write-Host "`n--- Environment Variables ---"
    try {
        $envVars = Get-ChildItem Env:* | Sort-Object Name
        $system.EnvVars = $envVars
        $envVars | Out-Host
    } catch {}

    Write-Host "`n--- Optional Windows Features (admin only) ---"
    if (!(Require-Admin "Get-WindowsOptionalFeature")) {
        try {
            $feats = Get-WindowsOptionalFeature -Online
            $system.OptionalFeatures = $feats
            $feats | Out-Host
        }
        catch {
            Write-Warning "Get-WindowsOptionalFeature encountered an error."
        }
    }

    # Example: Searching for “interesting files” in user dirs
    # (Instead of listing entire directories.)
    Write-Host "`n--- Searching for interesting files in Desktop/Documents/Downloads ---"
    $interestingPatterns = @("*.kdbx", "*.config", "*.creds", "*.credentials", "*.secret", "*pass*")
    $foundFiles = @()
    foreach ($dir in @("Desktop","Documents","Downloads")) {
        $path = Join-Path $env:USERPROFILE $dir
        if (Test-Path $path) {
            Write-Host "[*] Scanning $dir for $($interestingPatterns -join ', ')"
            foreach ($pattern in $interestingPatterns) {
                try {
                    $foundFiles += Get-ChildItem $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                }
                catch {}
            }
        }
    }
    $system.InterestingFiles = $foundFiles
    if ($foundFiles) {
        Write-Host "[+] Found $($foundFiles.Count) possible sensitive files:"
        $foundFiles | Out-Host
    }
    else {
        Write-Host "[-] No interesting files found."
    }

    Write-Host "`n--- Last Shutdown Events (6006, 6008) ---"
    try {
        $shutEvts = Get-WinEvent -LogName System -MaxEvents 20 -FilterXPath "*[System[(EventID=6006 or EventID=6008)]]"
        $system.ShutdownEvents = $shutEvts
        $shutEvts | Out-Host
    } catch {}

    $report.System = $system
    #endregion

    Write-Host "`n"

    #region [SECURITY]
    Write-Host "=== [SECURITY SETTINGS] ==="
    $security = [ordered]@{}

    Write-Host "`n--- AMSI Providers ---"
    try {
        $amsi = Get-Item "HKLM:\Software\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        $security.AMSIProviders = $amsi
        $amsi | Out-Host
    } catch {}

    Write-Host "`n--- Defender / AV ---"
    try {
        $defBasic = Get-MpComputerStatus -ErrorAction SilentlyContinue | 
                    Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled
        $security.Defender = $defBasic
        $defBasic | Out-Host
    } catch {}

    Write-Host "`n--- AppLocker (admin only) ---"
    $applockerInfo = [ordered]@{}
    if (!(Require-Admin "AppLocker")) {
        try {
            $svc = Get-Service "AppIDSvc" -ErrorAction SilentlyContinue
            if ($svc) {
                $applockerInfo.ServiceStatus = $svc.Status
                Write-Host "[+] AppLocker Service: $($svc.Status)"
                $policy = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
                $applockerInfo.PolicyXml = $policy
                Write-Host "[+] AppLocker Policy (XML):"
                Write-Host $policy
            }
        }
        catch {
            Write-Warning "AppLocker check encountered an error."
        }
    }
    $security.AppLocker = $applockerInfo

    Write-Host "`n--- LSA Registry Settings ---"
    try {
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
        $security.LSA = $lsa
        $lsa | Out-Host
    } catch {}

    Write-Host "`n--- Audit Policies (auditpol /get) ---"
    if (!(Require-Admin "auditpol /get")) {
        try {
            $audPol = auditpol /get /category:* 2>&1
            $security.AuditPolicies = $audPol
            $audPol | Out-Host
        }
        catch {
            Write-Warning "Audit Policy check encountered an error."
        }
    }

    Write-Host "`n--- NTLM (LmCompatibilityLevel) ---"
    try {
        $ntlm = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        $security.NTLM = $ntlm
        $ntlm | Out-Host
    } catch {}

    Write-Host "`n--- Secure Boot ---"
    try {
        $sb = Confirm-SecureBootUEFI
        $security.SecureBoot = $sb
        Write-Host "SecureBoot: $sb"
    } catch {
        $security.SecureBoot = "Not accessible or not supported"
        Write-Warning "Secure Boot check not accessible."
    }

    Write-Host "`n--- UAC Settings ---"
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        $security.UAC = $uac
        $uac | Out-Host
    } catch {}

    Write-Host "`n--- Windows Firewall (enabled rules, admin only) ---"
    if (!(Require-Admin "Get-NetFirewallRule")) {
        try {
            $fwRules = Get-NetFirewallRule | Where-Object Enabled -eq 'True'
            $security.FirewallRules = $fwRules
            $fwRules | Out-Host
        } catch {}
    }

    Write-Host "`n--- Defender Detailed ---"
    try {
        $defDet = Get-MpComputerStatus
        $security.DefenderDetailed = $defDet
        $defDet | Out-Host
    } catch {}

    Write-Host "`n--- Credential Guard (admin only) ---"
    if (!(Require-Admin "Get-WmiObject Win32_DeviceGuard")) {
        try {
            $cg = Get-WmiObject -Namespace "Root\Microsoft\Windows\DeviceGuard" -Class Win32_DeviceGuard -ErrorAction SilentlyContinue
            $security.CredentialGuard = $cg
            $cg | Out-Host
        }
        catch {
            Write-Warning "Credential Guard check encountered an error."
        }
    }

    $report.Security = $security
    #endregion

    Write-Host "`n"

    #region [NETWORK]
    Write-Host "=== [NETWORK INFORMATION] ==="
    $network = [ordered]@{}

    Write-Host "`n--- ARP Table ---"
    try {
        $arpOut = arp -a
        $network.ARP = $arpOut
        Write-Host $arpOut
    } catch {}

    Write-Host "`n--- TCP Connections ---"
    try {
        $tcpCon = Get-NetTCPConnection
        $network.TCPConnections = $tcpCon
        $tcpCon | Out-Host
    } catch {}

    Write-Host "`n--- UDP Endpoints ---"
    try {
        $udpCon = Get-NetUDPEndpoint
        $network.UDPConnections = $udpCon
        $udpCon | Out-Host
    } catch {}

    Write-Host "`n--- DNS Cache ---"
    try {
        $dnsCache = Get-DnsClientCache
        $network.DNSCache = $dnsCache
        $dnsCache | Out-Host
    } catch {}

    Write-Host "`n--- Network Profiles ---"
    try {
        $netProfs = Get-NetConnectionProfile
        $network.Profiles = $netProfs
        $netProfs | Out-Host
    } catch {}

    Write-Host "`n--- Network Shares (net share) ---"
    try {
        $sh = net share
        $network.Shares = $sh
        Write-Host $sh
    } catch {}

    Write-Host "`n--- IP Configuration ---"
    try {
        $ipCfg = Get-NetIPConfiguration
        $network.IPConfiguration = $ipCfg
        $ipCfg | Out-Host
    } catch {}

    Write-Host "`n--- WiFi Profiles (netsh wlan show profiles) ---"
    try {
        $wifi = netsh wlan show profiles
        $network.WiFiProfiles = $wifi
        Write-Host $wifi
    } catch {}

    $report.Network = $network
    #endregion

    Write-Host "`n"

    #region [CREDENTIALS]
    Write-Host "=== [CREDENTIALS] ==="
    $creds = [ordered]@{}

    Write-Host "`n--- cmdkey /list ---"
    try {
        $ck = cmdkey /list 2>&1
        $creds.CmdKey = $ck
        Write-Host $ck
    } catch {}

    Write-Host "`n--- DPAPI Master Keys ---"
    try {
        $dpapiPath = Join-Path $env:APPDATA "Microsoft\Protect"
        $dpapiKeys = Get-ChildItem -Path $dpapiPath -Recurse -ErrorAction SilentlyContinue
        $creds.DPAPI = $dpapiKeys
        $dpapiKeys | Out-Host
    } catch {}

    Write-Host "`n--- Cloud Credentials (AWS, Azure, GCloud) ---"
    $cloudInfo = [ordered]@{ AWS=$null; Azure=$null; GCloud=$null }
    try {
        if (Test-Path "$env:USERPROFILE\.aws\credentials") {
            $cloudInfo.AWS = Get-Content "$env:USERPROFILE\.aws\credentials"
            Write-Host "`n[+] AWS credentials found:"
            $cloudInfo.AWS | Out-Host
        }
        if (Test-Path "$env:USERPROFILE\.azure\accessTokens.json") {
            $cloudInfo.Azure = Get-Content "$env:USERPROFILE\.azure\accessTokens.json"
            Write-Host "`n[+] Azure tokens found:"
            $cloudInfo.Azure | Out-Host
        }
        if (Test-Path "$env:APPDATA\gcloud\credentials.db") {
            $cloudInfo.GCloud = "Present"
            Write-Host "`n[+] GCloud credentials found."
        }
    } catch {}
    $creds.Cloud = $cloudInfo

    Write-Host "`n--- Windows Auto Logon (Winlogon) ---"
    try {
        $autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
        $creds.AutoLogon = $autoLogon
        $autoLogon | Out-Host
    } catch {}

    Write-Host "`n--- .cred Files in User Profile ---"
    try {
        $credFiles = Get-ChildItem -Path $env:USERPROFILE -Filter *.cred -Recurse -ErrorAction SilentlyContinue
        $creds.CredFiles = $credFiles
        $credFiles | Out-Host
    } catch {}

    Write-Host "`n--- LAPS (Get-AdmPwdPassword, admin only) ---"
    if (!(Require-Admin "Get-AdmPwdPassword (LAPS)")) {
        try {
            if (Get-Command Get-AdmPwdPassword -ErrorAction SilentlyContinue) {
                $laps = Get-AdmPwdPassword -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue
                $creds.LAPS = $laps
                $laps | Out-Host
            }
        } catch {}
    }

    $report.Credentials = $creds
    #endregion

    Write-Host "`n"

    #region [APPLICATIONS]
    Write-Host "=== [APPLICATIONS] ==="
    $apps = [ordered]@{}

    Write-Host "`n--- Browser Presence/Paths ---"
    $browsers = [ordered]@{
        Chrome  = [ordered]@{ History=$false; Bookmarks=$false }
        Firefox = [ordered]@{ Profiles=$false; Executable=$false }
        IE      = [ordered]@{ Favorites=$null; TypedURLs=$null }
    }
    $chromeHist  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    $chromeBmarks= "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
    if (Test-Path $chromeHist)   { $browsers.Chrome.History   = $true }
    if (Test-Path $chromeBmarks) { $browsers.Chrome.Bookmarks = $true }

    $ffProfile = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffProfile) { $browsers.Firefox.Profiles = $true }
    if (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") { $browsers.Firefox.Executable = $true }

    try {
        if (Test-Path "$env:USERPROFILE\Favorites") {
            $fav = Get-ChildItem "$env:USERPROFILE\Favorites" -ErrorAction SilentlyContinue
            $browsers.IE.Favorites = $fav
        }
        $typedUrls = Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue
        $browsers.IE.TypedURLs = $typedUrls
    } catch {}

    Write-Host "Chrome  -> History:$($browsers.Chrome.History), Bookmarks:$($browsers.Chrome.Bookmarks)"
    Write-Host "Firefox -> Profiles:$($browsers.Firefox.Profiles), Executable:$($browsers.Firefox.Executable)"

    if ($browsers.IE.Favorites) {
        Write-Host "`n[+] IE Favorites:"
        $browsers.IE.Favorites | Out-Host
    }
    if ($browsers.IE.TypedURLs) {
        Write-Host "`n[+] IE Typed URLs:"
        $browsers.IE.TypedURLs | Out-Host
    }

    $apps.Browsers = $browsers

    Write-Host "`n--- Office & OneNote ---"
    $officeObj = [ordered]@{
        MRUs    = $null
        OneNote = (Test-Path "C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE")
    }
    try {
        $officeMRUs = Get-ChildItem "HKCU:\Software\Microsoft\Office" -Recurse -ErrorAction SilentlyContinue |
                      Where-Object { $_.Property -match "MRU" }
        $officeObj.MRUs = $officeMRUs
        Write-Host "OneNote present: $($officeObj.OneNote)"
        Write-Host "`n[+] Office MRUs:"
        $officeMRUs | Out-Host
    } catch {}
    $apps.Office = $officeObj

    Write-Host "`n--- Outlook Files ---"
    try {
        $outlookDir = "$env:USERPROFILE\Documents\Outlook Files"
        if (Test-Path $outlookDir) {
            $oFiles = Get-ChildItem -Path $outlookDir -Recurse -ErrorAction SilentlyContinue
            $apps.OutlookFiles = $oFiles
            Write-Host "[+] Outlook Files Found:"
            $oFiles | Out-Host
        }
    } catch {}

    Write-Host "`n--- FileZilla ---"
    try {
        $fzPath = "$env:APPDATA\FileZilla"
        if (Test-Path $fzPath) {
            $apps.FileZilla = "FileZilla present at $fzPath"
            Write-Host "[+] $($apps.FileZilla)"
        }
    } catch {}

    Write-Host "`n--- KeePass ---"
    try {
        $kpExe = "C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe"
        if (Test-Path $kpExe) {
            $apps.KeePass = "Found at $kpExe"
            Write-Host "[+] KeePass found at $kpExe"
        }
        else {
            $apps.KeePass = "Not found"
        }
        $kdbx = Get-ChildItem -Path "$env:USERPROFILE\Documents" -Filter *.kdbx -Recurse -ErrorAction SilentlyContinue
        if ($kdbx) {
            $apps.KeePassDBs = $kdbx
            Write-Host "`n[+] KeePass .kdbx Files in Documents:"
            $kdbx | Out-Host
        }
    } catch {}

    Write-Host "`n--- Slack ---"
    try {
        $slack = "$env:APPDATA\Slack"
        if (Test-Path $slack) {
            $apps.Slack = "Slack found at $slack"
            Write-Host $apps.Slack
        }
    } catch {}

    $report.Applications = $apps
    #endregion

    Write-Host "`n"

    #region [DIAGNOSTICS]
    Write-Host "=== [DIAGNOSTICS: Processes, Services, Sysmon, WMI, etc.] ==="
    $diag = [ordered]@{}

    Write-Host "`n--- Processes + Owners ---"
    try {
        $pAll = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $procList = foreach ($p in $pAll) {
            $owner = $p | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name  = $p.Name
                PID   = $p.ProcessId
                Owner = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
                Path  = $p.ExecutablePath
            }
        }
        $diag.Processes = $procList
        $procList | Out-Host
    } catch {}

    Write-Host "`n--- Services ---"
    try {
        $svc = Get-Service
        $diag.Services = $svc
        $svc | Out-Host
    } catch {}

    Write-Host "`n--- Sysmon ---"
    try {
        $sysmonSvc = Get-Service "Sysmon" -ErrorAction SilentlyContinue
        if ($sysmonSvc) {
            $diag.SysmonService = $sysmonSvc.Status
            Write-Host "[+] Sysmon Service: $($sysmonSvc.Status)"
            $sysmonEvt = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue
            $diag.SysmonEvents = $sysmonEvt
            Write-Host "`n[+] Sysmon Events (up to 100):"
            $sysmonEvt | Out-Host
        }
        else {
            $diag.SysmonService = "Not Installed"
            Write-Host "[-] Sysmon not installed or not running."
        }
    } catch {}

    Write-Host "`n--- WMI Event Consumers/Filters (admin only) ---"
    if (!(Require-Admin "WMI Subscription")) {
        try {
            $cons = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
            $filt = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
            $diag.WMIConsumers = $cons
            $diag.WMIFilters   = $filt
            Write-Host "`n[+] __EventConsumer objects:"
            $cons | Out-Host
            Write-Host "`n[+] __EventFilter objects:"
            $filt | Out-Host
        }
        catch {
            Write-Warning "WMI enumeration encountered an error."
        }
    }

    Write-Host "`n--- PowerShell Operational Log (up to 50) ---"
    try {
        $psOps = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue
        $diag.PSEvents = $psOps
        $psOps | Out-Host
    } catch {}

    Write-Host "`n--- PowerShell History (ConsoleHost_history.txt) ---"
    try {
        $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $histPath) {
            $phist = Get-Content $histPath
            $diag.PSHistory = $phist
            Write-Host "`n[+] PowerShell History:"
            $phist | Out-Host
        }
    } catch {}

    Write-Host "`n--- Named Pipes (\\.\pipe\) ---"
    try {
        $pipes = Get-ChildItem -Path "\\.\pipe\" -ErrorAction SilentlyContinue
        $diag.NamedPipes = $pipes
        $pipes | Out-Host
    } catch {}

    Write-Host "`n--- Search Index (WSearch) ---"
    try {
        $wSearchSvc = Get-Service "WSearch" -ErrorAction SilentlyContinue
        $diag.SearchIndexService = $wSearchSvc
        Write-Host $wSearchSvc | Out-String
    } catch {}

    Write-Host "`n--- Scheduled Tasks (non-disabled) ---"
    try {
        $sched = Get-ScheduledTask | Where-Object State -ne 'Disabled'
        $diag.ScheduledTasks = $sched
        $sched | Out-Host
    } catch {}

    Write-Host "`n--- AutoRuns (HKLM & HKCU) ---"
    $autoRunsObj = [ordered]@{HKLM=$null; HKCU=$null}
    try {
        $arHklm = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        $autoRunsObj.HKLM = $arHklm
        Write-Host "`n[+] HKLM:Run"
        $arHklm | Out-Host
    } catch {}
    try {
        $arHkcu = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        $autoRunsObj.HKCU = $arHkcu
        Write-Host "`n[+] HKCU:Run"
        $arHkcu | Out-Host
    } catch {}
    $diag.AutoRuns = $autoRunsObj

    Write-Host "`n--- Installed Products (Win32_Product, admin only) ---"
    if (!(Require-Admin "Win32_Product")) {
        try {
            $prods = Get-WmiObject Win32_Product -ErrorAction SilentlyContinue | Select-Object Name, Version, InstallDate
            $diag.Win32Product = $prods
            $prods | Out-Host
        }
        catch {
            Write-Warning "Win32_Product encountered an error."
        }
    }

    Write-Host "`n--- Security Log (Last 50) ---"
    try {
        $secLog = Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue
        $diag.SecurityLog = $secLog
        $secLog | Out-Host
    } catch {}

    Write-Host "`n--- Printers ---"
    try {
        $prn = Get-Printer -ErrorAction SilentlyContinue
        $diag.Printers = $prn
        $prn | Out-Host
    } catch {}

    Write-Host "`n--- Ntoskrnl info ---"
    try {
        $ntos = Get-ChildItem "$env:WINDIR\system32\ntoskrnl.exe" -ErrorAction SilentlyContinue
        $diag.Ntoskrnl = $ntos
        $ntos | Out-Host
    } catch {}

    $report.Diagnostics = $diag
    #endregion

    Write-Host "`n"

    #region [ENTERPRISE]
    Write-Host "=== [ENTERPRISE FEATURES] ==="
    $enterprise = [ordered]@{}

    Write-Host "`n--- gpresult /z (admin only) ---"
    if (!(Require-Admin "gpresult /z")) {
        try {
            $gpRes = gpresult /z 2>&1
            $enterprise.GPResult = $gpRes
            Write-Host $gpRes
        }
        catch {}
    }

    Write-Host "`n--- dsregcmd /status ---"
    try {
        $dsreg = dsregcmd /status 2>&1
        $enterprise.DsregcmdStatus = $dsreg
        Write-Host $dsreg
    } catch {}

    Write-Host "`n--- Local Groups & Users ---"
    try {
        $lg = Get-LocalGroup -ErrorAction SilentlyContinue
        $lu = Get-LocalUser -ErrorAction SilentlyContinue
        $enterprise.LocalGroups = $lg
        $enterprise.LocalUsers  = $lu
        Write-Host "`n[+] Local Groups:"
        $lg | Out-Host
        Write-Host "`n[+] Local Users:"
        $lu | Out-Host
    } catch {}

    Write-Host "`n--- Mapped Drives (Win32_MappedLogicalDisk, admin only) ---"
    if (!(Require-Admin "Get-WmiObject Win32_MappedLogicalDisk")) {
        try {
            $mapped = Get-WmiObject Win32_MappedLogicalDisk -ErrorAction SilentlyContinue
            $enterprise.MappedDrives = $mapped
            $mapped | Out-Host
        }
        catch {}
    }

    Write-Host "`n--- RDP Sessions (qwinsta) ---"
    try {
        $qwinsta = qwinsta 2>&1
        $enterprise.RDPSessions = $qwinsta
        Write-Host $qwinsta
    } catch {}

    Write-Host "`n--- RDP Settings (HKLM:\Software\Microsoft\Terminal Server Client) ---"
    try {
        $rdpSet = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Terminal Server Client" -ErrorAction SilentlyContinue
        $enterprise.RDPSettings = $rdpSet
        $rdpSet | Out-Host
    } catch {}

    Write-Host "`n--- RDCMan Files ---"
    try {
        $rdcPath = Join-Path $env:LOCALAPPDATA "Microsoft\RDCMan"
        if (Test-Path $rdcPath) {
            $rdcFiles = Get-ChildItem -Path $rdcPath -Recurse -ErrorAction SilentlyContinue
            $enterprise.RDCManFiles = $rdcFiles
            $rdcFiles | Out-Host
        }
    } catch {}

    Write-Host "`n--- RDP Saved Connections (Cache) ---"
    try {
        $rdpCache = Join-Path $env:APPDATA "Microsoft\Terminal Server Client\Cache"
        if (Test-Path $rdpCache) {
            $cacheFiles = Get-ChildItem -Path $rdpCache -Recurse -ErrorAction SilentlyContinue
            $enterprise.RDPCache = $cacheFiles
            $cacheFiles | Out-Host
        }
    } catch {}

    Write-Host "`n--- WSUS Settings ---"
    $wsusObj = [ordered]@{ Server=$null; Enabled=$null }
    try {
        $wsusObj.Server  = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
        $wsusObj.Enabled = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "UseWUServer"
        Write-Host $wsusObj | Out-Host
    } catch {}
    $enterprise.WSUS = $wsusObj

    $report.Enterprise = $enterprise
    #endregion

    Write-Host "`n"

    #region [MISC]
    Write-Host "=== [MISCELLANEOUS] ==="
    $misc = [ordered]@{}

    Write-Host "`n--- Certificates (Cert:\) admin only ---"
    if (!(Require-Admin "Certificate Enumeration")) {
        try {
            $certs = Get-ChildItem -Path Cert:\ -Recurse -ErrorAction SilentlyContinue |
                     Select-Object Subject, Thumbprint, NotAfter
            $misc.Certificates = $certs
            $certs | Out-Host
        }
        catch {}
    }

    Write-Host "`n--- Explorer RunMRU ---"
    try {
        $runMRU = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
        $misc.ExplorerRunMRU = $runMRU
        $runMRU | Out-Host
    } catch {}

    Write-Host "`n--- Recycle Bin (C:\$Recycle.Bin, admin only) ---"
    if (!(Require-Admin "Recycle Bin")) {
        try {
            $rb = Get-ChildItem -Path "C:\$Recycle.Bin" -Recurse -ErrorAction SilentlyContinue
            $misc.RecycleBin = $rb
            $rb | Out-Host
        }
        catch {}
    }

    Write-Host "`n--- Tokens & Privileges (whoami /groups + /priv) ---"
    try {
        $tg = whoami /groups
        $tp = whoami /priv
        $misc.TokenGroups = $tg
        $misc.TokenPrivs  = $tp
        Write-Host "`n[+] whoami /groups:"
        Write-Host $tg
        Write-Host "`n[+] whoami /priv:"
        Write-Host $tp
    } catch {}

    Write-Host "`n--- LOLBAS in System32 (admin only) ---"
    if (!(Require-Admin "LOLBAS check in System32")) {
        try {
            $lolbasRegex = "at|bitsadmin|certutil|cmd|mshta|powershell|cscript|wscript|regsvr32|regasm|installutil|msbuild|schtasks"
            $lolbasFound = Get-ChildItem "C:\Windows\System32" -Filter *.exe -Recurse -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -match $lolbasRegex } |
                           Select-Object Name, FullName
            $misc.LOLBAS = $lolbasFound
            $lolbasFound | Out-Host
        }
        catch {}
    }

    $report.Misc = $misc
    #endregion

    Write-Host "`n=================================================="
    Write-Host "[*] Enumeration complete. Transcript => $TextOutputFile, JSON => $OutputFile"

    #region [Stop Transcript]
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        Write-Host "[!] Could not stop transcript."
    }
    #endregion

    #region [Write JSON]
    try {
        $report | ConvertTo-Json -Depth 8 | Out-File $OutputFile -Encoding UTF8
        Write-Host "[+] JSON saved to: $OutputFile"
    }
    catch {
        Write-Host "[!] Failed to write JSON output." -ForegroundColor Red
    }
    #endregion
}

# If run directly, call the function:
if ($MyInvocation.InvocationName -eq '.\SeatbeltPS_Everything.ps1') {
    Invoke-SeatbeltPS
}
