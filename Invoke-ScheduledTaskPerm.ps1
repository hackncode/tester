function Get-ScheduledTaskPermissions {
    # Get current user
    $CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
    Write-Host "[INFO] Checking scheduled tasks and file permissions for user: $CurrentUser" -ForegroundColor Cyan

    Get-ScheduledTask | ForEach-Object {
        $TaskName = $_.TaskName
        $User = $_.Principal.UserId
        $ExecutePath = ($_.Actions | Where-Object { $_.Execute }) | Select-Object -ExpandProperty Execute
        $Arguments = ($_.Actions | Where-Object { $_.Arguments }) | Select-Object -ExpandProperty Arguments

        # Resolve environment variables (if any)
        if ($ExecutePath) {
            $ResolvedExecPath = [System.Environment]::ExpandEnvironmentVariables($ExecutePath)

            # Get ACL permissions for the execution path
            $UserHasPermissions = $false
            try {
                $ACL = Get-Acl -Path $ResolvedExecPath -ErrorAction Stop
                $UserPermissions = $ACL.Access | Where-Object {
                    $_.IdentityReference -match $CurrentUser -and 
                    ($_.FileSystemRights -match "Write|Modify|FullControl")
                }
                if ($UserPermissions) { $UserHasPermissions = $true }
            } catch {
                $ResolvedExecPath = "[NOT FOUND]"
            }

            [PSCustomObject]@{
                TaskName      = $TaskName
                User          = $User
                CanModify     = if ($UserHasPermissions) { "YES" } else { "NO" }
                Execute       = $ResolvedExecPath
                Arguments     = $Arguments
            }
        }
    } | Format-Table -AutoSize
}

# Run the function
Get-ScheduledTaskPermissions
