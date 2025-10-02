# =============================================================================
# CA Identity Manager PowerShell Automation Tools
# Complete toolkit for bulk user operations and password management
# PowerShell 5.1 Compatible
# =============================================================================

# =============================================================================
# CONFIGURATION SECTION - UPDATE THESE VALUES USING YOUR DISCOVERY RESULTS
# =============================================================================

$Global:CAIMConfig = @{
    # ===== SERVER INFORMATION =====
    BaseURL = "https://your-caim-server.company.com"
    Domain = "your-caim-server.company.com"
    Protocol = "https:"
    
    # ===== PAGE PATHS =====
    LoginPath = "/iam/im/login.jsp"
    UserSearchPath = "/iam/im/user/search"
    UserManagementPath = "/iam/im/user/manage"
    UserDetailsPath = "/iam/im/user/details"
    PasswordResetPath = "/iam/im/user/resetPassword"
    AccountUnlockPath = "/iam/im/user/unlock"
    
    # ===== AUTHENTICATION CONFIGURATION =====
    LoginFormAction = ""
    LoginFormMethod = "POST"
    LoginFormId = "loginForm"
    UsernameField = "username"
    PasswordField = "password"
    CsrfTokenField = "csrf_token"
    RememberMeField = "rememberMe"
    
    # ===== SEARCH CONFIGURATION =====
    SearchFormAction = ""
    SearchUsernameField = "searchUsername"
    SearchSubmitButton = "searchButton"
    SearchTypeField = "searchType"
    SearchTypeValue = "username"
    
    # ===== USER MANAGEMENT CONFIGURATION =====
    ManagementFormAction = ""
    UserIdField = "userId"
    ActionField = "action"
    UnlockActionValue = "unlock"
    ResetPasswordActionValue = "resetPassword"
    NewPasswordField = "newPassword"
    ConfirmPasswordField = "confirmPassword"
    ForcePasswordChangeField = "forcePasswordChange"
    
    # ===== SESSION MANAGEMENT =====
    SessionCookieName = "JSESSIONID"
    SessionTimeout = 30
    MaxConcurrentSessions = 1
    
    # ===== REQUEST SETTINGS =====
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    RequestTimeout = 30
    RetryAttempts = 3
    RetryDelay = 2
    RateLimitDelay = 1
    
    # ===== API CONFIGURATION =====
    ApiEnabled = $false
    ApiBaseUrl = ""
    ApiAuthEndpoint = "/api/auth"
    ApiUsersEndpoint = "/api/users"
    ApiTokenHeader = "X-Auth-Token"
    
    # ===== LOGGING AND OUTPUT =====
    LogLevel = "Info"
    LogFile = "CAIM_Operations_{0:yyyyMMdd}.log"
    ResultsDirectory = "CAIM_Results"
    BackupResults = $true
    
    # ===== SECURITY SETTINGS =====
    VerifySSLCertificate = $true
    AllowedDomains = @()
    EncryptPasswords = $true
    
    # ===== BULK OPERATION SETTINGS =====
    BatchSize = 50
    BatchDelay = 5
    MaxConcurrentRequests = 5
    ProgressReporting = $true
    
    # ===== PASSWORD POLICY =====
    DefaultPasswordLength = 12
    PasswordComplexity = $true
    PasswordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    ExcludeAmbiguousChars = $true
    
    # ===== DISCOVERY RESULTS =====
    DiscoveredLoginFields = @()
    DiscoveredSearchFields = @()
    DiscoveredManagementFields = @()
    DiscoveredButtons = @()
    DiscoveredLinks = @()
}

# =============================================================================
# UTILITY FUNCTIONS (Defined first to avoid ordering issues)
# =============================================================================

function Write-CAIMLog {
    <#
    .SYNOPSIS
        Writes log messages to file and console
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file if configured
    if ($Global:CAIMConfig.LogFile) {
        try {
            $logPath = $Global:CAIMConfig.LogFile -f (Get-Date)
            $logDir = Split-Path $logPath -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $logPath -Value $logEntry -Force -ErrorAction SilentlyContinue
        } catch {
            # Silently fail to avoid recursion
        }
    }
    
    # Write to console based on level
    if (-not $NoConsole) {
        switch ($Level) {
            "Debug" { if ($Global:CAIMConfig.LogLevel -eq "Debug") { Write-Host $logEntry -ForegroundColor Gray } }
            "Info" { Write-Verbose $logEntry -Verbose:$true }
            "Warning" { Write-Warning $Message }
            "Error" { Write-Error $Message -ErrorAction Continue }
        }
    }
}

function New-CAIMRandomPassword {
    <#
    .SYNOPSIS
        Generates a random password meeting complexity requirements
    #>
    
    param(
        [Parameter(Mandatory=$false)]
        [int]$Length = 0,
        
        [Parameter(Mandatory=$false)]
        [bool]$ExcludeAmbiguous = $null
    )
    
    if ($Length -eq 0) { $Length = $Global:CAIMConfig.DefaultPasswordLength }
    if ($null -eq $ExcludeAmbiguous) { $ExcludeAmbiguous = $Global:CAIMConfig.ExcludeAmbiguousChars }
    
    $chars = $Global:CAIMConfig.PasswordChars
    
    if ($ExcludeAmbiguous) {
        $chars = $chars -replace '[0OIl1|`"]', ''
    }
    
    if ($Global:CAIMConfig.PasswordComplexity) {
        $upper = "ABCDEFGHIJKLMNPQRSTUVWXYZ"
        $lower = "abcdefghijkmnopqrstuvwxyz"
        $digits = "23456789"
        $special = "!@#$%^&*"
        
        $password = ""
        $password += $upper[(Get-Random -Maximum $upper.Length)]
        $password += $lower[(Get-Random -Maximum $lower.Length)]
        $password += $digits[(Get-Random -Maximum $digits.Length)]
        $password += $special[(Get-Random -Maximum $special.Length)]
        
        for ($i = 4; $i -lt $Length; $i++) {
            $password += $chars[(Get-Random -Maximum $chars.Length)]
        }
        
        # Shuffle
        $passwordArray = $password.ToCharArray()
        for ($i = 0; $i -lt $passwordArray.Length; $i++) {
            $j = Get-Random -Maximum $passwordArray.Length
            $temp = $passwordArray[$i]
            $passwordArray[$i] = $passwordArray[$j]
            $passwordArray[$j] = $temp
        }
        
        return -join $passwordArray
    } else {
        $password = ""
        for ($i = 0; $i -lt $Length; $i++) {
            $password += $chars[(Get-Random -Maximum $chars.Length)]
        }
        return $password
    }
}

function ConvertFrom-CAIMSecureString {
    <#
    .SYNOPSIS
        Safely converts SecureString to plain text (PS 5.1 compatible)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [Security.SecureString]$SecureString
    )
    
    try {
        # Use NetworkCredential method - works reliably in PS 5.1
        $credential = New-Object System.Net.NetworkCredential("", $SecureString)
        return $credential.Password
    } catch {
        Write-CAIMLog -Level "Error" -Message "Failed to convert SecureString: $($_.Exception.Message)"
        throw
    }
}

function Clear-CAIMSensitiveString {
    <#
    .SYNOPSIS
        Securely clears sensitive string from memory
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ref]$StringVariable
    )
    
    if ($StringVariable.Value) {
        # Overwrite with zeros
        $length = $StringVariable.Value.Length
        $StringVariable.Value = "0" * $length
        $StringVariable.Value = $null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

# =============================================================================
# VALIDATION AND INITIALIZATION FUNCTIONS
# =============================================================================

function Test-CAIMConfiguration {
    <#
    .SYNOPSIS
        Validates the CA IM configuration settings
    #>
    
    Write-Host "🔍 Validating CA Identity Manager Configuration..." -ForegroundColor Yellow
    
    $issues = @()
    $warnings = @()
    
    if ($Global:CAIMConfig.BaseURL -eq "https://your-caim-server.company.com") {
        $issues += "BaseURL must be updated with your actual CA IM server URL"
    }
    
    if ($Global:CAIMConfig.LoginPath -eq "/iam/im/login.jsp") {
        $warnings += "LoginPath is using default value - verify this matches your system"
    }
    
    if ($Global:CAIMConfig.UsernameField -eq "username") {
        $warnings += "UsernameField is using default value - verify from discovery results"
    }
    
    # URL validation
    try {
        $uri = [System.Uri]::new($Global:CAIMConfig.BaseURL)
        if (-not ($uri.Scheme -eq "https" -or $uri.Scheme -eq "http")) {
            $issues += "BaseURL must include protocol (http:// or https://)"
        }
    } catch {
        $issues += "BaseURL is not a valid URL format"
    }
    
    # Directory validation
    if ($Global:CAIMConfig.ResultsDirectory -and -not (Test-Path $Global:CAIMConfig.ResultsDirectory)) {
        try {
            New-Item -ItemType Directory -Path $Global:CAIMConfig.ResultsDirectory -Force | Out-Null
            Write-Host "✅ Created results directory: $($Global:CAIMConfig.ResultsDirectory)" -ForegroundColor Green
        } catch {
            $warnings += "Could not create results directory: $($Global:CAIMConfig.ResultsDirectory)"
        }
    }
    
    if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
        Write-Host "✅ Configuration validation passed!" -ForegroundColor Green
        return $true
    } else {
        if ($issues.Count -gt 0) {
            Write-Host "❌ Critical configuration issues:" -ForegroundColor Red
            $issues | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        }
        
        if ($warnings.Count -gt 0) {
            Write-Host "⚠️  Configuration warnings:" -ForegroundColor Yellow
            $warnings | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
        }
        
        return ($issues.Count -eq 0)
    }
}

function Initialize-CAIMConfiguration {
    <#
    .SYNOPSIS
        Interactive configuration setup and validation
    #>
    
    Write-Host "🚀 CA Identity Manager Configuration Setup" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    
    Write-Host "`nCurrent Configuration:" -ForegroundColor Yellow
    Write-Host "Base URL: $($Global:CAIMConfig.BaseURL)" -ForegroundColor White
    Write-Host "Domain: $($Global:CAIMConfig.Domain)" -ForegroundColor White
    Write-Host "Login Path: $($Global:CAIMConfig.LoginPath)" -ForegroundColor White
    Write-Host "Search Path: $($Global:CAIMConfig.UserSearchPath)" -ForegroundColor White
    Write-Host "Management Path: $($Global:CAIMConfig.UserManagementPath)" -ForegroundColor White
    
    Write-Host "`nField Configuration:" -ForegroundColor Yellow
    Write-Host "Username Field: $($Global:CAIMConfig.UsernameField)" -ForegroundColor White
    Write-Host "Password Field: $($Global:CAIMConfig.PasswordField)" -ForegroundColor White
    Write-Host "Search Field: $($Global:CAIMConfig.SearchUsernameField)" -ForegroundColor White
    
    $isValid = Test-CAIMConfiguration
    
    Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
    if (-not $isValid) {
        Write-Host "1. Use the Discovery Tool to gather your CA IM system details" -ForegroundColor Yellow
        Write-Host "2. Update the configuration values at the top of this script" -ForegroundColor Yellow  
        Write-Host "3. Run Initialize-CAIMConfiguration again to validate" -ForegroundColor Yellow
    } else {
        Write-Host "1. Test connection: Connect-CAIM" -ForegroundColor Green
        Write-Host "2. Try a search: Search-CAIMUser -Username 'testuser'" -ForegroundColor Green
        Write-Host "3. Run Show-CAIMExamples for more usage examples" -ForegroundColor Green
    }
    
    return $isValid
}

# =============================================================================
# SSL CERTIFICATE BYPASS FOR PS 5.1 (if needed)
# =============================================================================

function Disable-CAIMCertificateValidation {
    <#
    .SYNOPSIS
        Disables SSL certificate validation for PS 5.1 (use with caution)
    #>
    
    if (-not $Global:CAIMConfig.VerifySSLCertificate) {
        Write-Host "⚠️  Disabling SSL certificate validation" -ForegroundColor Yellow
        
        try {
            # PS 5.1 method to bypass certificate validation
            add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            
            Write-CAIMLog -Level "Warning" -Message "SSL certificate validation disabled"
        } catch {
            # Already loaded or failed to load
        }
    }
}

# =============================================================================
# CORE CONNECTIVITY FUNCTIONS
# =============================================================================

function Connect-CAIM {
    <#
    .SYNOPSIS
        Establishes connection to CA Identity Manager
    #>
    
    param(
        [Parameter(Mandatory=$false)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [Security.SecureString]$Password,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    if ($Credential) {
        $Username = $Credential.UserName
        $Password = $Credential.Password
    }
    
    if (-not $Username -or -not $Password) {
        $Credential = Get-Credential -Message "Enter CA Identity Manager admin credentials"
        if (-not $Credential) {
            Write-Host "❌ Authentication cancelled" -ForegroundColor Red
            return $false
        }
        $Username = $Credential.UserName
        $Password = $Credential.Password
    }
    
    Write-Host "🔐 Connecting to CA Identity Manager..." -ForegroundColor Yellow
    Write-Host "Server: $($Global:CAIMConfig.BaseURL)" -ForegroundColor Cyan
    
    # Validate configuration
    if (-not (Test-CAIMConfiguration)) {
        Write-Host "❌ Cannot connect - configuration validation failed" -ForegroundColor Red
        return $false
    }
    
    # Handle SSL certificate validation
    Disable-CAIMCertificateValidation
    
    $plainPassword = $null
    
    try {
        # Initialize web session
        $CAIMSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        
        # Get login page
        $loginPageUrl = $Global:CAIMConfig.BaseURL + $Global:CAIMConfig.LoginPath
        Write-Host "📄 Retrieving login page..." -ForegroundColor Cyan
        
        $loginPageParams = @{
            Uri = $loginPageUrl
            SessionVariable = 'tempSession'
            UseBasicParsing = $true
            UserAgent = $Global:CAIMConfig.UserAgent
            TimeoutSec = $Global:CAIMConfig.RequestTimeout
            ErrorAction = 'Stop'
        }
        
        $loginPage = Invoke-WebRequest @loginPageParams
        $CAIMSession = $tempSession
        
        # Extract CSRF token
        $csrfToken = ""
        $csrfPatterns = @(
            'name="' + $Global:CAIMConfig.CsrfTokenField + '".*?value="([^"]+)"',
            'name="csrf.*?".*?value="([^"]+)"',
            'csrfToken.*?value="([^"]+)"'
        )
        
        foreach ($pattern in $csrfPatterns) {
            if ($loginPage.Content -match $pattern) {
                $csrfToken = $matches[1]
                Write-Host "🔒 Found CSRF token" -ForegroundColor Green
                break
            }
        }
        
        # Convert SecureString to plain text (PS 5.1 compatible method)
        $plainPassword = ConvertFrom-CAIMSecureString -SecureString $Password
        
        # Build login form data
        $loginData = @{
            $Global:CAIMConfig.UsernameField = $Username
            $Global:CAIMConfig.PasswordField = $plainPassword
        }
        
        if ($csrfToken -and $Global:CAIMConfig.CsrfTokenField) {
            $loginData[$Global:CAIMConfig.CsrfTokenField] = $csrfToken
        }
        
        # Perform login
        Write-Host "🔑 Authenticating user: $Username" -ForegroundColor Cyan
        
        $loginParams = @{
            Uri = $loginPageUrl
            Method = 'POST'
            Body = $loginData
            WebSession = $CAIMSession
            UseBasicParsing = $true
            UserAgent = $Global:CAIMConfig.UserAgent
            TimeoutSec = $Global:CAIMConfig.RequestTimeout
            ErrorAction = 'Stop'
        }
        
        $loginResponse = Invoke-WebRequest @loginParams
        
        # Check for successful authentication
        $authSuccess = $false
        if ($loginResponse.StatusCode -eq 200 -and 
            $loginResponse.Content -notmatch "login.*error|invalid.*credentials|authentication.*failed") {
            $authSuccess = $true
        }
        
        if ($authSuccess) {
            Write-Host "✅ Successfully connected to CA Identity Manager" -ForegroundColor Green
            Write-Host "👤 Authenticated as: $Username" -ForegroundColor Green
            
            $Global:CAIMSession = $CAIMSession
            $Global:CAIMAuthenticatedUser = $Username
            $Global:CAIMAuthenticationTime = Get-Date
            
            Write-CAIMLog -Level "Info" -Message "User $Username successfully authenticated to CA IM"
            
            return $true
        } else {
            Write-Host "❌ Authentication failed" -ForegroundColor Red
            Write-Host "Status Code: $($loginResponse.StatusCode)" -ForegroundColor Yellow
            Write-CAIMLog -Level "Error" -Message "Authentication failed for user: $Username"
            return $false
        }
        
    } catch {
        Write-Host "❌ Connection error: $($_.Exception.Message)" -ForegroundColor Red
        Write-CAIMLog -Level "Error" -Message "Connection failed: $($_.Exception.Message)"
        return $false
    } finally {
        # Securely clear password
        if ($plainPassword) {
            $passwordRef = [ref]$plainPassword
            Clear-CAIMSensitiveString -StringVariable $passwordRef
        }
    }
}

function Test-CAIMConnection {
    <#
    .SYNOPSIS
        Tests if CA IM session is still active
    #>
    
    if (-not $Global:CAIMSession) {
        return $false
    }
    
    if ($Global:CAIMAuthenticationTime) {
        $sessionAge = (Get-Date) - $Global:CAIMAuthenticationTime
        if ($sessionAge.TotalMinutes -gt $Global:CAIMConfig.SessionTimeout) {
            return $false
        }
    }
    
    return $true
}

# =============================================================================
# USER MANAGEMENT FUNCTIONS
# =============================================================================

function Search-CAIMUser {
    <#
    .SYNOPSIS
        Searches for users in CA Identity Manager
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [string]$SearchType = "username"
    )
    
    if (-not (Test-CAIMConnection)) {
        Write-Host "❌ Not connected. Please run Connect-CAIM first." -ForegroundColor Red
        return $null
    }
    
    Write-Host "🔍 Searching for user: $Username" -ForegroundColor Cyan
    
    try {
        $searchUrl = $Global:CAIMConfig.BaseURL + $Global:CAIMConfig.UserSearchPath
        $searchParams = @{
            $Global:CAIMConfig.SearchUsernameField = $Username
        }
        
        if ($Global:CAIMConfig.SearchTypeField) {
            $searchParams[$Global:CAIMConfig.SearchTypeField] = $SearchType
        }
        
        $response = Invoke-WebRequest -Uri $searchUrl -Method GET -Body $searchParams -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeout -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ User search completed for: $Username" -ForegroundColor Green
            
            $userInfo = @{
                Username = $Username
                Found = $true
                SearchResponse = $response.Content
                LastSearched = Get-Date
            }
            
            Write-CAIMLog -Level "Info" -Message "User search completed: $Username"
            return $userInfo
        }
        
    } catch {
        Write-Host "❌ Search error for user $Username : $($_.Exception.Message)" -ForegroundColor Red
        Write-CAIMLog -Level "Error" -Message "Search failed for $Username : $($_.Exception.Message)"
        return $null
    }
}

function Unlock-CAIMUser {
    <#
    .SYNOPSIS
        Unlocks a user account in CA Identity Manager
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    if (-not (Test-CAIMConnection)) {
        Write-Host "❌ Not connected. Please run Connect-CAIM first." -ForegroundColor Red
        return $false
    }
    
    Write-Host "🔓 Attempting to unlock user: $Username" -ForegroundColor Yellow
    
    try {
        $unlockUrl = $Global:CAIMConfig.BaseURL + $Global:CAIMConfig.AccountUnlockPath
        $unlockData = @{
            $Global:CAIMConfig.UserIdField = $Username
            $Global:CAIMConfig.ActionField = $Global:CAIMConfig.UnlockActionValue
        }
        
        $response = Invoke-WebRequest -Uri $unlockUrl -Method POST -Body $unlockData -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeout -ErrorAction Stop
        
        $successPatterns = @("success", "unlocked", "completed", "successful")
        $errorPatterns = @("error", "failed", "invalid", "denied")
        
        $isSuccess = $false
        $hasError = $false
        
        foreach ($pattern in $successPatterns) {
            if ($response.Content -match $pattern) {
                $isSuccess = $true
                break
            }
        }
        
        foreach ($pattern in $errorPatterns) {
            if ($response.Content -match $pattern) {
                $hasError = $true
                break
            }
        }
        
        if ($response.StatusCode -eq 200 -and $isSuccess -and -not $hasError) {
            Write-Host "✅ Successfully unlocked user: $Username" -ForegroundColor Green
            Write-CAIMLog -Level "Info" -Message "User unlocked successfully: $Username"
            Start-Sleep -Seconds $Global:CAIMConfig.RateLimitDelay
            return $true
        } else {
            Write-Host "❌ Failed to unlock user: $Username" -ForegroundColor Red
            Write-CAIMLog -Level "Warning" -Message "Unlock failed for user: $Username"
            return $false
        }
        
    } catch {
        Write-Host "❌ Unlock error for user $Username : $($_.Exception.Message)" -ForegroundColor Red
        Write-CAIMLog -Level "Error" -Message "Unlock error for $Username : $($_.Exception.Message)"
        return $false
    }
}

function Reset-CAIMUserPassword {
    <#
    .SYNOPSIS
        Resets user password in CA Identity Manager
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [string]$NewPassword = $null,
        
        [Parameter(Mandatory=$false)]
        [bool]$ForceChange = $true
    )
    
    if (-not (Test-CAIMConnection)) {
        Write-Host "❌ Not connected. Please run Connect-CAIM first." -ForegroundColor Red
        return @{ Success = $false; Username = $Username; Error = "Not connected" }
    }
    
    Write-Host "🔐 Attempting to reset password for user: $Username" -ForegroundColor Yellow
    
    $passwordToUse = $null
    
    try {
        # Generate password if none provided
        if (-not $NewPassword) {
            $passwordToUse = New-CAIMRandomPassword
            Write-Host "🎲 Generated temporary password" -ForegroundColor Cyan
        } else {
            $passwordToUse = $NewPassword
        }
        
        $resetUrl = $Global:CAIMConfig.BaseURL + $Global:CAIMConfig.PasswordResetPath
        $resetData = @{
            $Global:CAIMConfig.UserIdField = $Username
            $Global:CAIMConfig.ActionField = $Global:CAIMConfig.ResetPasswordActionValue
            $Global:CAIMConfig.NewPasswordField = $passwordToUse
        }
        
        if ($Global:CAIMConfig.ConfirmPasswordField) {
            $resetData[$Global:CAIMConfig.ConfirmPasswordField] = $passwordToUse
        }
        
        if ($Global:CAIMConfig.ForcePasswordChangeField) {
            $resetData[$Global:CAIMConfig.ForcePasswordChangeField] = $ForceChange.ToString().ToLower()
        }
        
        $response = Invoke-WebRequest -Uri $resetUrl -Method POST -Body $resetData -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeout -ErrorAction Stop
        
        $successPatterns = @("success", "reset", "completed", "updated")
        $errorPatterns = @("error", "failed", "invalid", "denied")
        
        $isSuccess = $false
        $hasError = $false
        
        foreach ($pattern in $successPatterns) {
            if ($response.Content -match $pattern) {
                $isSuccess = $true
                break
            }
        }
        
        foreach ($pattern in $errorPatterns) {
            if ($response.Content -match $pattern) {
                $hasError = $true
                break
            }
        }
        
        if ($response.StatusCode -eq 200 -and $isSuccess -and -not $hasError) {
            Write-Host "✅ Successfully reset password for user: $Username" -ForegroundColor Green
            Write-CAIMLog -Level "Info" -Message "Password reset successfully: $Username"
            Start-Sleep -Seconds $Global:CAIMConfig.RateLimitDelay
            
            return @{
                Success = $true
                Username = $Username
                TempPassword = if ($Global:CAIMConfig.EncryptPasswords) { "***ENCRYPTED***" } else { $passwordToUse }
                ForceChange = $ForceChange
                Timestamp = Get-Date
            }
        } else {
            Write-Host "❌ Failed to reset password for user: $Username" -ForegroundColor Red
            Write-CAIMLog -Level "Warning" -Message "Password reset failed for user: $Username"
            return @{ Success = $false; Username = $Username; Error = "Reset operation failed" }
        }
        
    } catch {
        Write-Host "❌ Password reset error for user $Username : $($_.Exception.Message)" -ForegroundColor Red
        Write-CAIMLog -Level "Error" -Message "Password reset error for $Username : $($_.Exception.Message)"
        return @{ Success = $false; Username = $Username; Error = $_.Exception.Message }
    } finally {
        # Securely clear password
        if ($passwordToUse) {
            $passwordRef = [ref]$passwordToUse
            Clear-CAIMSensitiveString -StringVariable $passwordRef
        }
    }
}

# =============================================================================
# BULK OPERATION FUNCTIONS
# =============================================================================

function Process-BulkCAIMActions {
    <#
    .SYNOPSIS
        Processes bulk user actions from CSV file
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Unlock", "ResetPassword", "Both")]
        [string]$Action,
        
        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 0,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ""
    )
    
    if (-not (Test-CAIMConnection)) {
        Write-Host "❌ Not connected. Please run Connect-CAIM first." -ForegroundColor Red
        return
    }
    
    if (-not (Test-Path $CsvFilePath)) {
        Write-Host "❌ CSV file not found: $CsvFilePath" -ForegroundColor Red
        return
    }
    
    # Fixed: Validate BatchSize to prevent division by zero
    if ($BatchSize -le 0) {
        $BatchSize = $Global:CAIMConfig.BatchSize
    }
    
    if ($BatchSize -le 0) {
        $BatchSize = 50  # Fallback default
    }
    
    # Generate output path if not specified
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = Join-Path $Global:CAIMConfig.ResultsDirectory "CAIM_BulkResults_$Action_$timestamp.csv"
    }
    
    try {
        $users = Import-Csv $CsvFilePath
        $totalUsers = $users.Count
        
        # Fixed: Check for empty user list
        if ($totalUsers -eq 0) {
            Write-Host "⚠️  No users found in CSV file" -ForegroundColor Yellow
            return @()
        }
        
        $results = @()
        $successCount = 0
        $failureCount = 0
        
        Write-Host "🚀 Starting bulk operation: $Action" -ForegroundColor Cyan
        Write-Host "📊 Processing $totalUsers users in batches of $BatchSize" -ForegroundColor Cyan
        Write-Host "📁 Results will be saved to: $OutputPath" -ForegroundColor Cyan
        
        # Create results directory
        $resultsDir = Split-Path $OutputPath -Parent
        if ($resultsDir -and -not (Test-Path $resultsDir)) {
            New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
        }
        
        # Process users in batches
        for ($i = 0; $i -lt $totalUsers; $i += $BatchSize) {
            $batchEnd = [Math]::Min($i + $BatchSize - 1, $totalUsers - 1)
            $batchNumber = [Math]::Floor($i / $BatchSize) + 1
            $totalBatches = [Math]::Ceiling($totalUsers / $BatchSize)
            
            Write-Host "`n📦 Processing Batch $batchNumber of $totalBatches (Users $($i+1)-$($batchEnd+1))" -ForegroundColor Yellow
            
            if ($Global:CAIMConfig.ProgressReporting) {
                $percentComplete = [Math]::Round(($i / $totalUsers) * 100, 1)
                Write-Progress -Activity "Processing Bulk Actions" -Status "$percentComplete% Complete" -PercentComplete $percentComplete -CurrentOperation "Batch $batchNumber of $totalBatches"
            }
            
            $batchUsers = $users[$i..$batchEnd]
            
            foreach ($userRow in $batchUsers) {
                $username = $userRow.Username.Trim()
                if (-not $username) {
                    Write-Host "⚠️  Skipping empty username" -ForegroundColor Yellow
                    continue
                }
                
                Write-Host "👤 Processing user: $username" -ForegroundColor Cyan
                
                $result = @{
                    Username = $username
                    ProcessedDate = Get-Date
                    Action = $Action
                    UnlockResult = "N/A"
                    UnlockError = ""
                    ResetResult = "N/A"
                    ResetError = ""
                    TempPassword = ""
                    BatchNumber = $batchNumber
                    ProcessingOrder = $i + 1
                }
                
                # Perform unlock if requested
                if ($Action -eq "Unlock" -or $Action -eq "Both") {
                    try {
                        $unlockSuccess = Unlock-CAIMUser -Username $username
                        if ($unlockSuccess) {
                            $result.UnlockResult = "Success"
                            Write-Host "  ✅ Unlock: Success" -ForegroundColor Green
                        } else {
                            $result.UnlockResult = "Failed"
                            $result.UnlockError = "Unlock operation returned false"
                            Write-Host "  ❌ Unlock: Failed" -ForegroundColor Red
                            $failureCount++
                        }
                    } catch {
                        $result.UnlockResult = "Error"
                        $result.UnlockError = $_.Exception.Message
                        Write-Host "  ❌ Unlock: Error - $($_.Exception.Message)" -ForegroundColor Red
                        $failureCount++
                    }
                }
                
                # Perform password reset if requested
                if ($Action -eq "ResetPassword" -or $Action -eq "Both") {
                    try {
                        $resetResult = Reset-CAIMUserPassword -Username $username
                        if ($resetResult.Success) {
                            $result.ResetResult = "Success"
                            $result.TempPassword = $resetResult.TempPassword
                            Write-Host "  ✅ Password Reset: Success" -ForegroundColor Green
                        } else {
                            $result.ResetResult = "Failed"
                            $result.ResetError = $resetResult.Error
                            Write-Host "  ❌ Password Reset: Failed" -ForegroundColor Red
                            $failureCount++
                        }
                    } catch {
                        $result.ResetResult = "Error"
                        $result.ResetError = $_.Exception.Message
                        Write-Host "  ❌ Password Reset: Error - $($_.Exception.Message)" -ForegroundColor Red
                        $failureCount++
                    }
                }
                
                # Count successes
                if (($result.UnlockResult -eq "Success" -or $result.UnlockResult -eq "N/A") -and 
                    ($result.ResetResult -eq "Success" -or $result.ResetResult -eq "N/A")) {
                    $successCount++
                }
                
                $results += New-Object PSObject -Property $result
                
                Start-Sleep -Milliseconds ($Global:CAIMConfig.RateLimitDelay * 1000)
            }
            
            # Pause between batches
            if ($batchNumber -lt $totalBatches) {
                Write-Host "⏸️  Pausing $($Global:CAIMConfig.BatchDelay) seconds between batches..." -ForegroundColor Cyan
                Start-Sleep -Seconds $Global:CAIMConfig.BatchDelay
            }
        }
        
        if ($Global:CAIMConfig.ProgressReporting) {
            Write-Progress -Activity "Processing Bulk Actions" -Completed
        }
        
        # Export results
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        # Display summary
        Write-Host "`n📊 BULK OPERATION SUMMARY" -ForegroundColor Green
        Write-Host "=========================" -ForegroundColor Green
        Write-Host "Total Users Processed: $totalUsers" -ForegroundColor White
        Write-Host "Successful Operations: $successCount" -ForegroundColor Green
        Write-Host "Failed Operations: $failureCount" -ForegroundColor Red
        Write-Host "Success Rate: $([Math]::Round(($successCount / $totalUsers) * 100, 1))%" -ForegroundColor Cyan
        Write-Host "Results saved to: $OutputPath" -ForegroundColor Yellow
        
        Write-CAIMLog -Level "Info" -Message "Bulk operation completed: $Action for $totalUsers users. Success: $successCount, Failed: $failureCount"
        
        return $results
        
    } catch {
        Write-Host "❌ Bulk operation error: $($_.Exception.Message)" -ForegroundColor Red
        Write-CAIMLog -Level "Error" -Message "Bulk operation failed: $($_.Exception.Message)"
        throw
    }
}

function Get-CAIMPasswordExpiry {
    <#
    .SYNOPSIS
        Checks password expiry for multiple users
    .DESCRIPTION
        NOTE: This function contains placeholder parsing logic that must be customized
        for your specific CA IM system's response format before use.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Usernames,
        
        [Parameter(Mandatory=$false)]
        [int]$ExpiryThreshold = 30,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ""
    )
    
    if (-not (Test-CAIMConnection)) {
        Write-Host "❌ Not connected. Please run Connect-CAIM first." -ForegroundColor Red
        return
    }
    
    $totalUsers = $Usernames.Count
    
    # Fixed: Check for empty user list
    if ($totalUsers -eq 0) {
        Write-Host "⚠️  No usernames provided" -ForegroundColor Yellow
        return @()
    }
    
    # Generate output path
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = Join-Path $Global:CAIMConfig.ResultsDirectory "CAIM_PasswordExpiry_$timestamp.csv"
    }
    
    $results = @()
    $expiringSoon = 0
    $expired = 0
    
    Write-Host "🔐 Checking password expiry for $totalUsers users" -ForegroundColor Cyan
    Write-Host "⏰ Expiry threshold: $ExpiryThreshold days" -ForegroundColor Cyan
    Write-Host "⚠️  WARNING: This function uses placeholder parsing logic." -ForegroundColor Yellow
    Write-Host "   You must customize the response parsing for your CA IM system!" -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $totalUsers; $i++) {
        $username = $Usernames[$i].Trim()
        
        if ($Global:CAIMConfig.ProgressReporting) {
            $percentComplete = [Math]::Round(($i / $totalUsers) * 100, 1)
            Write-Progress -Activity "Checking Password Expiry" -Status "$percentComplete% Complete" -PercentComplete $percentComplete -CurrentOperation "User: $username"
        }
        
        Write-Host "🔍 Checking: $username" -ForegroundColor Cyan
        
        try {
            $userInfoUrl = $Global:CAIMConfig.BaseURL + $Global:CAIMConfig.UserDetailsPath + "?user=$username"
            $response = Invoke-WebRequest -Uri $userInfoUrl -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeout -ErrorAction Stop
            
            $expiryInfo = @{
                Username = $username
                PasswordExpiry = "Unknown - Customize parsing"
                DaysUntilExpiry = "Unknown - Customize parsing"
                Status = "Requires Customization"
                LastPasswordChange = "Unknown"
                CheckDate = Get-Date
                AccountLocked = "Unknown"
                AccountEnabled = "Unknown"
                LastLogin = "Unknown"
                Note = "Response parsing needs customization for your CA IM system"
            }
            
            # PLACEHOLDER: Customize these patterns for your CA IM system
            # Example patterns - adjust to match your actual response format:
            # if ($response.Content -match 'passwordExpiry["\s:]+([0-9/\-]+)') { ... }
            
            $results += New-Object PSObject -Property $expiryInfo
            
            Write-Host "  ⚠️  Status: Requires Customization" -ForegroundColor Yellow
            
        } catch {
            Write-Host "  ❌ Error checking $username : $($_.Exception.Message)" -ForegroundColor Red
            Write-CAIMLog -Level "Error" -Message "Password expiry check failed for $username : $($_.Exception.Message)"
            
            $results += New-Object PSObject -Property @{
                Username = $username
                PasswordExpiry = "Error"
                DaysUntilExpiry = "Error"
                Status = "Error"
                CheckDate = Get-Date
                Error = $_.Exception.Message
            }
        }
        
        Start-Sleep -Milliseconds ($Global:CAIMConfig.RateLimitDelay * 500)
    }
    
    if ($Global:CAIMConfig.ProgressReporting) {
        Write-Progress -Activity "Checking Password Expiry" -Completed
    }
    
    # Export results
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    
    Write-Host "`n📊 PASSWORD EXPIRY CHECK COMPLETED" -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Green
    Write-Host "Total Users Checked: $totalUsers" -ForegroundColor White
    Write-Host "⚠️  Results require response parsing customization" -ForegroundColor Yellow
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Cyan
    
    Write-CAIMLog -Level "Info" -Message "Password expiry check completed for $totalUsers users (requires customization)"
    
    return $results
}

# =============================================================================
# HELP AND EXAMPLES
# =============================================================================

function Show-CAIMExamples {
    <#
    .SYNOPSIS
        Displays usage examples and help information
    #>
    
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CA Identity Manager PowerShell Tools                      ║
║                              Usage Examples                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

🔧 SETUP AND CONFIGURATION
═══════════════════════════════
1. Initialize and validate configuration:
   Initialize-CAIMConfiguration

2. Test configuration:
   Test-CAIMConfiguration

🔐 CONNECTION AND AUTHENTICATION
═══════════════════════════════════
1. Connect with prompted credentials:
   Connect-CAIM

2. Connect with existing credentials:
   `$cred = Get-Credential
   Connect-CAIM -Credential `$cred

3. Test active connection:
   Test-CAIMConnection

👤 INDIVIDUAL USER OPERATIONS
═════════════════════════════════
1. Search for a user:
   Search-CAIMUser -Username "jsmith"

2. Unlock a user account:
   Unlock-CAIMUser -Username "jsmith"

3. Reset user password (generates random password):
   Reset-CAIMUserPassword -Username "jsmith"

4. Reset with specific password:
   Reset-CAIMUserPassword -Username "jsmith" -NewPassword "TempPass123!"

📊 BULK OPERATIONS
═══════════════════
1. Create CSV file with usernames:
   Username
   jsmith
   mjohnson
   bwilliams

2. Process bulk unlock:
   Process-BulkCAIMActions -CsvFilePath "C:\temp\users.csv" -Action "Unlock"

3. Process bulk password reset:
   Process-BulkCAIMActions -CsvFilePath "C:\temp\users.csv" -Action "ResetPassword"

4. Process both unlock and reset:
   Process-BulkCAIMActions -CsvFilePath "C:\temp\users.csv" -Action "Both"

5. Custom batch size and output:
   Process-BulkCAIMActions -CsvFilePath "users.csv" -Action "Both" -BatchSize 25 -OutputPath "results.csv"

🔐 PASSWORD EXPIRY MONITORING
═══════════════════════════════════
NOTE: Get-CAIMPasswordExpiry requires customization before use!

1. Check expiry for specific users:
   Get-CAIMPasswordExpiry -Usernames @("jsmith", "mjohnson")

2. Check with custom threshold:
   Get-CAIMPasswordExpiry -Usernames @("user1", "user2") -ExpiryThreshold 14

🛠️  UTILITY FUNCTIONS
════════════════════
1. Generate random password:
   New-CAIMRandomPassword

2. Generate specific length password:
   New-CAIMRandomPassword -Length 16

3. View this help:
   Show-CAIMExamples

📁 FILE FORMATS
════════════════
CSV Input Format:
Username
jsmith
mjohnson
bwilliams

Results Output includes:
- Username
- Action performed
- Success/failure status
- Temporary passwords (if applicable)
- Timestamps
- Error details

🔍 TROUBLESHOOTING
═══════════════════
If you encounter issues:
1. Run Test-CAIMConfiguration to check setup
2. Use Initialize-CAIMConfiguration for guided setup  
3. Check log files in the configured results directory
4. Verify field names match your CA IM system using the Discovery Tool
5. Test individual operations before bulk processing

📚 CONFIGURATION
═════════════════
All settings are in the `$Global:CAIMConfig hashtable at the top of this script.
Use the Discovery Tool (HTML file) to gather the correct values for your system.

"@ -ForegroundColor Green
}

# =============================================================================
# INITIALIZATION
# =============================================================================

Write-Host "🚀 CA Identity Manager PowerShell Tools Loaded!" -ForegroundColor Green
Write-Host "📋 Run 'Show-CAIMExamples' to see usage examples" -ForegroundColor Cyan
Write-Host "⚙️  Run 'Initialize-CAIMConfiguration' to validate your setup" -ForegroundColor Yellow

if ($Global:CAIMConfig.BaseURL -eq "https://your-caim-server.company.com") {
    Write-Host "⚠️  Configuration required - please update the settings at the top of this script" -ForegroundColor Yellow
    Write-Host "🔍 Use the Discovery Tool to gather your system details" -ForegroundColor Cyan
}
