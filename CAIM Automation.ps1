# =============================================================================
# CA Identity Manager PowerShell Automation Tools
# Complete toolkit for bulk user operations and password management
# PowerShell 5.1 Compatible
# =============================================================================

# =============================================================================
# CONFIGURATION SECTION - THIS BLOCK IS REPLACED BY THE DISCOVERY TOOL OUTPUT
# =============================================================================

$Global:CAIMConfig = @{
    # ===== SERVER INFORMATION (Discovered) =====
    BaseURL               = "https://your-caim-server.company.com"
    
    # ===== ACTION URLS (Discovered) =====
    LoginPageURL          = "https://your-caim-server.company.com/iam/im/login.jsp"
    SearchRequestURL      = "https://your-caim-server.company.com/iam/im/user/search"
    UnlockUserActionURL   = "UPDATE_URL_FOR_UNLOCK_ACTION"
    ResetPasswordActionURL= "UPDATE_URL_FOR_RESET_ACTION"

    # ===== FORM FIELDS (Discovered) =====
    UsernameField         = "username"
    PasswordField         = "password"
    CsrfTokenField        = "csrf_token" # IMPORTANT: Set to "" if no CSRF token is used
    SearchField           = "searchUsername"
    SearchFormMethod      = "POST"
    
    # ===== USER MANAGEMENT FIELDS (Common Defaults - VERIFY) =====
    UserIdField           = "userId"
    ActionField           = "action"
    UnlockActionValue     = "unlock"
    ResetPasswordActionValue = "resetPassword"
    NewPasswordField      = "newPassword"
    ConfirmPasswordField  = "confirmPassword"

    # ===== SCRIPT SETTINGS (Defaults) =====
    UserAgent             = "PowerShell-CAIM-Automation/1.0"
    RequestTimeoutSec     = 60
    VerifySSLCertificate  = $true 
}

# =============================================================================
# UTILITY FUNCTIONS (Defined first to avoid ordering issues)
# =============================================================================

function Write-CAIMLog {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level,
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    # This is a simplified logger for demonstration. A full implementation would handle file paths.
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
}

# =============================================================================
# SSL CERTIFICATE BYPASS FOR PS 5.1 (if needed)
# =============================================================================

function Disable-CAIMCertificateValidation {
    if (-not $Global:CAIMConfig.VerifySSLCertificate) {
        Write-Host "⚠️  Disabling SSL certificate validation as per configuration." -ForegroundColor Yellow
        try {
            add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(ServicePoint srv, X509Certificate cert, WebRequest req, int problem) { return true; }
                }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        } catch { /* Type already added */ }
    }
}

# =============================================================================
# CORE CONNECTIVITY FUNCTIONS
# =============================================================================

function Connect-CAIM {
    param(
        [Parameter(Mandatory=$false)] [string]$Username,
        [Parameter(Mandatory=$false)] [Security.SecureString]$Password,
        [Parameter(Mandatory=$false)] [System.Management.Automation.PSCredential]$Credential
    )
    
    if ($Credential) {
        $Username = $Credential.UserName
        $Password = $Credential.Password
    }
    
    if (-not $Username -or -not $Password) {
        $Credential = Get-Credential -Message "Enter CA Identity Manager admin credentials"
        if (-not $Credential) { Write-Host "❌ Authentication cancelled." -ForegroundColor Red; return $false }
        $Username = $Credential.UserName
        $Password = $Credential.Password
    }
    
    Write-Host "🔐 Connecting to CA Identity Manager..." -ForegroundColor Yellow
    Disable-CAIMCertificateValidation
    
    $plainPassword = $null
    try {
        # Get login page to capture session and CSRF token
        $loginPageParams = @{
            Uri             = $Global:CAIMConfig.LoginPageURL
            SessionVariable = 'caimSession'
            UseBasicParsing = $true
            UserAgent       = $Global:CAIMConfig.UserAgent
            TimeoutSec      = $Global:CAIMConfig.RequestTimeoutSec
            ErrorAction     = 'Stop'
        }
        $loginPage = Invoke-WebRequest @loginPageParams
        
        $loginData = @{}
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        $loginData[$Global:CAIMConfig.UsernameField] = $Username
        $loginData[$Global:CAIMConfig.PasswordField] = $plainPassword

        # Extract CSRF token if configured
        if ($Global:CAIMConfig.CsrfTokenField -and $Global:CAIMConfig.CsrfTokenField -ne "") {
            $csrfPattern = 'name="' + [regex]::Escape($Global:CAIMConfig.CsrfTokenField) + '".*?value="([^"]+)"'
            if ($loginPage.Content -match $csrfPattern) {
                $loginData[$Global:CAIMConfig.CsrfTokenField] = $matches[1]
                Write-Host "🔒 Found and added CSRF token." -ForegroundColor Green
            } else {
                Write-Warning "CSRF token field specified but not found on the page."
            }
        }
        
        # Perform login
        Write-Host "🔑 Authenticating user: $Username" -ForegroundColor Cyan
        $loginParams = @{
            Uri             = $Global:CAIMConfig.LoginPageURL
            Method          = 'POST'
            Body            = $loginData
            WebSession      = $caimSession
            UseBasicParsing = $true
            UserAgent       = $Global:CAIMConfig.UserAgent
            TimeoutSec      = $Global:CAIMConfig.RequestTimeoutSec
            ErrorAction     = 'Stop'
        }
        $loginResponse = Invoke-WebRequest @loginParams
        
        if ($loginResponse.StatusCode -eq 200 -and $loginResponse.Content -notmatch "login.*error|invalid.*credentials|authentication.*failed") {
            Write-Host "✅ Successfully connected to CA Identity Manager." -ForegroundColor Green
            $Global:CAIMSession = $caimSession
            return $true
        } else {
            Write-Host "❌ Authentication failed. Check credentials or configuration." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Connection error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        if ($plainPassword) { $plainPassword = $null; [System.GC]::Collect() }
    }
}

function Test-CAIMConnection {
    if (-not $Global:CAIMSession) { return $false }
    try {
        # A lightweight request to a known page to see if the session is valid
        $testUrl = $Global:CAIMConfig.BaseURL
        Invoke-WebRequest -Uri $testUrl -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# =============================================================================
# USER MANAGEMENT FUNCTIONS
# =============================================================================

function Search-CAIMUser {
    param(
        [Parameter(Mandatory=$true)] [string]$Username
    )
    
    if (-not (Test-CAIMConnection)) { Write-Host "❌ Not connected. Run Connect-CAIM." -ForegroundColor Red; return $null }
    
    Write-Host "🔍 Searching for user: $Username" -ForegroundColor Cyan
    try {
        $searchData = @{
            $Global:CAIMConfig.SearchField = $Username
        }
        
        $searchParams = @{
            Uri             = $Global:CAIMConfig.SearchRequestURL
            Method          = $Global:CAIMConfig.SearchFormMethod
            WebSession      = $Global:CAIMSession
            UseBasicParsing = $true
            TimeoutSec      = $Global:CAIMConfig.RequestTimeoutSec
            ErrorAction     = 'Stop'
        }
        
        if ($Global:CAIMConfig.SearchFormMethod -eq 'POST') {
            $searchParams.Body = $searchData
        } else {
            # For GET, append to URI
            $queryString = ($searchData.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '&'
            $searchParams.Uri = "$($searchParams.Uri)?$queryString"
        }
        
        $response = Invoke-WebRequest @searchParams
        
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ User search completed for: $Username" -ForegroundColor Green
            # NOTE: Parsing the result requires custom logic based on the HTML response
            return $response.Content
        }
    } catch {
        Write-Host "❌ Search error for user $Username: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Unlock-CAIMUser {
    param(
        [Parameter(Mandatory=$true)] [string]$Username
    )
    if (-not (Test-CAIMConnection)) { Write-Host "❌ Not connected. Run Connect-CAIM." -ForegroundColor Red; return $false }
    
    Write-Host "🔓 Attempting to unlock user: $Username" -ForegroundColor Yellow
    try {
        $unlockData = @{
            $Global:CAIMConfig.UserIdField = $Username
            $Global:CAIMConfig.ActionField = $Global:CAIMConfig.UnlockActionValue
        }
        
        $response = Invoke-WebRequest -Uri $Global:CAIMConfig.UnlockUserActionURL -Method POST -Body $unlockData -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeoutSec -ErrorAction Stop
        
        if ($response.StatusCode -eq 200 -and $response.Content -match "success|unlocked") {
            Write-Host "✅ Successfully unlocked user: $Username" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Failed to unlock user: $Username" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Unlock error for user $Username: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Reset-CAIMUserPassword {
    param(
        [Parameter(Mandatory=$true)] [string]$Username,
        [Parameter(Mandatory=$true)] [string]$NewPassword
    )
    if (-not (Test-CAIMConnection)) { Write-Host "❌ Not connected. Run Connect-CAIM." -ForegroundColor Red; return $false }
    
    Write-Host "🔐 Attempting to reset password for user: $Username" -ForegroundColor Yellow
    try {
        $resetData = @{
            $Global:CAIMConfig.UserIdField = $Username
            $Global:CAIMConfig.ActionField = $Global:CAIMConfig.ResetPasswordActionValue
            $Global:CAIMConfig.NewPasswordField = $NewPassword
            $Global:CAIMConfig.ConfirmPasswordField = $NewPassword
        }
        
        $response = Invoke-WebRequest -Uri $Global:CAIMConfig.ResetPasswordActionURL -Method POST -Body $resetData -WebSession $Global:CAIMSession -UseBasicParsing -TimeoutSec $Global:CAIMConfig.RequestTimeoutSec -ErrorAction Stop
        
        if ($response.StatusCode -eq 200 -and $response.Content -match "success|reset") {
            Write-Host "✅ Successfully reset password for user: $Username" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Failed to reset password for user: $Username" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Password reset error for user $Username: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
