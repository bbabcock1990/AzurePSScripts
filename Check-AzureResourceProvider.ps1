<#
.SYNOPSIS
    This script checks the availability of specified Azure resource providers and VM SKUs
    in a given Azure region, including core quota checks for VM families.

.DESCRIPTION
    The script first verifies that the required Az PowerShell modules are installed and
    then prompts the user to log in or select a subscription. It checks if a list of
    predefined resource providers and VM SKUs are available in a specified region.
    For VM SKUs, it also checks the core quota limits and usage to determine if there
    are enough cores available for a given workload.

.EXAMPLE
    PS C:\> .\Check-Azure-Providers.ps1
    The script will prompt you for the required inputs, such as the target region.

.NOTES
    Author: Brandon Babcock (Microsoft SE - Azure Infrastructure Specialist)
    Date: September 2025
    Version: 1.1.0

    Requires: Az PowerShell module (Az.Accounts, Az.Compute, Az.Resources, Az.Quota)
#>

# ==============================================================================
# 1. SCRIPT CONFIGURATION - EDIT THESE VARIABLES TO CUSTOMIZE THE CHECKS
# ==============================================================================

# Define the list of Azure resource providers to check.
# Format: "namespace/serviceType" or "namespace" for a provider-level check.
$global:ResourceProvidersToCheck = @(
    "microsoft.compute/disks",
    "microsoft.compute/virtualmachines",
    "microsoft.compute/virtualmachinescalesets",
    "microsoft.containerservice/managedclusters",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.keyvault/vaults",
    "microsoft.network/applicationgateways",
    "microsoft.network/azurefirewalls",
    "microsoft.network/bastionhosts",
    "microsoft.network/dnszones",
    "microsoft.network/loadbalancers",
    "microsoft.network/privatednszones",
    "microsoft.network/privateendpoints",
    "microsoft.network/publicipaddresses",
    "microsoft.operationalinsights/workspaces",
    "microsoft.recoveryservices/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.storage/storageaccounts/datalakegen2",
    "microsoft.web/sites",
    "microsoft.databricks"
)

# Define the list of VM SKUs to check, including the associated workload and required cores.
$global:SKUsToCheck = @(
    @{
        SKUName = "Standard_D8as_v6";
        Cores = 8;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
    @{
        SKUName = "Standard_D4as_v6";
        Cores = 4;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
    @{
        SKUName = "Standard_D8as_v5";
        Cores = 8;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
    @{
        SKUName = "Standard_D4as_v5";
        Cores = 4;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
     @{
        SKUName = "Standard_D8as_v4";
        Cores = 8;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
    @{
        SKUName = "Standard_D4as_v4";
        Cores = 4;
        ResourceType = "virtualMachines";
        Workload = "AKS node pools"
    },
    @{
        SKUName = "Standard_D2ds_v4";
        Cores = 2;
        ResourceType = "MySqlFlexibleServers";
        Workload = "MySQL DB"
    },
    @{
        SKUName = "Standard_D4as_v6";
        Cores = 4;
        ResourceType = "virtualMachines";
        Workload = "Kafka VM"
    },
    @{
        SKUName = "Standard_D8as_v5";
        Cores = 8;
        ResourceType = "virtualMachines";
        Workload = "Kafka VM"
    },
    @{
        SKUName = "Standard_B8ms";
        Cores = 8;
        ResourceType = "virtualMachines";
        Workload = "Jenkins Agent VM"
    }
)

# Define required PowerShell modules.
$global:RequiredModules = @("Az.Accounts", "Az.Compute", "Az.Resources", "Az.Quota")

# Add logging configuration
$global:LogFile = Join-Path $PSScriptRoot "AzureCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$global:MaxRetries = 3
$global:RetryWaitSeconds = 10

# Add caching variables
$global:CachedSkus = $null
$global:CachedQuotas = @{}

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    Add-Content -Path $global:LogFile -Value $logMessage
    Write-Host $logMessage
}

# ==============================================================================
# 2. CORE FUNCTIONS
#    These functions perform the primary logic of the script.
# ==============================================================================

function Test-AzureAvailability {
    <#
    .SYNOPSIS
        The main function to test resource provider and SKU availability.

    .DESCRIPTION
        This function orchestrates the entire process. It validates the region,
        registers the Quota provider, fetches all resource providers and SKUs,
        and then calls helper functions to perform the checks.

    .PARAMETER ResourceProviders
        A string array of resource providers to check.

    .PARAMETER Region
        The Azure region to check for availability.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ResourceProviders,
        
        [Parameter(Mandatory = $true)]
        [string]$Region
    )
    
    # Create arrays to store results
    $providerResults = @()

    # Validate and normalize region name
    try {
        $locations = Get-AzLocation
        $validRegion = $locations | Where-Object { $_.Location -eq $Region -or $_.DisplayName -eq $Region }
        
        if (-not $validRegion) {
            Write-Error "Invalid region '$Region'. Valid regions are:"
            $locations | Select-Object Location, DisplayName | Format-Table
            return
        }
        $normalizedRegion = $validRegion.Location
    }
    catch {
        Write-Error "Error validating region: $_"
        return
    }

    # Check if the Quota provider is already registered before attempting registration.
    $quotaProviderStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.Quota -ErrorAction SilentlyContinue
    if ($null -eq $quotaProviderStatus -or $quotaProviderStatus.RegistrationState -ne "Registered") {
        Write-Host "`nRegistering Microsoft.Quota resource provider...`n" -ForegroundColor Yellow
        Register-AzResourceProvider -ProviderNamespace Microsoft.Quota -ErrorAction Stop

        $timeout = New-TimeSpan -Minutes 5
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $isRegistered = $false

        do {
            Write-Host "Checking registration status... Waiting for Microsoft.Quota to be Registered." -ForegroundColor Gray
            $providerStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.Quota
            if ($providerStatus.RegistrationState -eq "Registered") {
                $isRegistered = $true
                Write-Host "`nMicrosoft.Quota is now registered." -ForegroundColor Green
            } else {
                Start-Sleep -Seconds 10
            }
        } while (-not $isRegistered -and $stopwatch.Elapsed -lt $timeout)

        if (-not $isRegistered) {
            Write-Error "Failed to register Microsoft.Quota provider within the timeout period."
            return
        }
    } else {
        Write-Host "`nMicrosoft.Quota is already registered. Skipping registration step." -ForegroundColor Green
    }

    # Get all resource providers once to improve performance
    try {
        $availableProviders = Get-AzResourceProvider
    }
    catch {
        Write-Error "Error fetching resource providers: $_"
        return
    }
    
    # Check resource provider availability
    Write-Host "`nChecking Resource Providers..." -ForegroundColor Cyan
    $totalProviders = $ResourceProviders.Count
    $currentProvider = 0

    foreach ($provider in $ResourceProviders) {
        $currentProvider++
        Write-Progress -Activity "Checking Resource Providers" -Status "Processing $provider" `
            -PercentComplete (($currentProvider / $totalProviders) * 100)

        try {
            $result = Determine-ProviderAvailability -Provider $provider -NormalizedRegion $normalizedRegion -AvailableProviders $availableProviders
            $providerResults += $result
        }
        catch {
            $providerResults += [PSCustomObject]@{
                ResourceProvider = $provider
                Region = $normalizedRegion
                Available = $false
                Error = $_.Exception.Message
            }
        }
    }

    Write-Progress -Activity "Checking Resource Providers" -Completed
    
    # Check VM SKUs
    $skuResults = Test-SkuAvailability -Region $normalizedRegion
    
    # Output the results using a dedicated function
    Format-OutputTable -ProviderResults $providerResults -SkuResults $skuResults -Region $normalizedRegion
}

# Enhance Test-SkuAvailability with parallel processing
function Test-SkuAvailability {
    param([string]$Region)

    Write-Progress -Activity "Checking VM Sizes and Quota" -Completed
    
    # Get subscription ID for quota scope
    $subscriptionId = (Get-AzContext).Subscription.Id
    $quotaScope = "/subscriptions/$subscriptionId/providers/Microsoft.Compute/locations/$Region"
    
    # Use cached SKUs if available
    if (-not $global:CachedSkus) {
        $global:CachedSkus = Get-AzComputeResourceSku -Location $Region -ErrorAction Stop
    }

    $results = foreach ($sku in $global:SKUsToCheck) {
        try {
            $skuName = $sku.SKUName
            $skuFound = $global:CachedSkus | Where-Object { $_.Name -eq $skuName }
            
            if ($skuFound) {
                # Enhanced quota check with retry logic
                $quota = $null
                $quotaUsage = $null
                $retryCount = 0
                
                # Get the SKU family for quota check
                $skuFamily = $skuFound.Family
                
                while (-not $quota -and $retryCount -lt $global:MaxRetries) {
                    try {
                        $quota = Get-AzQuota -Scope $quotaScope -ResourceName "$skuFamily" -ErrorAction Stop
                        $quotaUsage = Get-AzQuotaUsage -Scope $quotaScope -Name "$skuFamily" -ErrorAction SilentlyContinue
                        break
                    }
                    catch {
                        $retryCount++
                        if ($retryCount -lt $global:MaxRetries) {
                            Start-Sleep -Seconds $global:RetryWaitSeconds
                        }
                    }
                }

                # Calculate quota and availability
                $quotaLimit = if ($quota) { $quota.Limit.value } else { 0 }
                $currentUsage = if ($quotaUsage) { $quotaUsage.UsageValue } else { 0 }
                $remainingQuota = $quotaLimit - $currentUsage
                
                [PSCustomObject]@{
                    Workload = $sku.Workload
                    SKU = $skuName
                    Region = $Region
                    Available = $true
                    "Quota Available" = $quotaLimit
                    "Used Cores" = $currentUsage
                    "Required Cores" = $sku.Cores
                    "Delta" = $remainingQuota
                    Error = if (-not $quota) { "Unable to retrieve quota information" } else { $null }
                }
            } else {
                [PSCustomObject]@{
                    Workload = $sku.Workload
                    SKU = $skuName
                    Region = $Region
                    Available = $false
                    "Quota Available" = 0
                    "Used Cores" = 0
                    "Required Cores" = $sku.Cores
                    "Delta" = 0
                    Error = "SKU not available in region"
                }
            }
        }
        catch {
            Write-Log "Error processing SKU $skuName : $_" -Level "Error"
            [PSCustomObject]@{
                Workload = $sku.Workload
                SKU = $skuName
                Region = $Region
                Available = $false
                "Quota Available" = 0
                "Used Cores" = 0
                "Required Cores" = $sku.Cores
                "Delta" = 0
                Error = $_.Exception.Message
            }
        }
    }
    
    return $results
}

function Determine-ProviderAvailability {
    <#
    .SYNOPSIS
        Determines the availability of a resource provider in a region.

    .DESCRIPTION
        This helper function checks if a specific resource provider or
        service type is available within a given Azure region by examining
        the properties of available resource providers.

    .PARAMETER Provider
        The resource provider string (e.g., "microsoft.compute/virtualmachines").

    .PARAMETER NormalizedRegion
        The normalized region name (e.g., "westus2").

    .PARAMETER AvailableProviders
        A collection of all available resource providers, fetched once for performance.
    #>
    param (
        [string]$Provider,
        [string]$NormalizedRegion,
        [PSObject]$AvailableProviders
    )
    $providerInfo = Get-ResourceProviderInfo -ProviderString $Provider
    $namespace = $providerInfo.Namespace
    $serviceType = $providerInfo.ServiceType

    $providerExists = $AvailableProviders | Where-Object { $_.ProviderNamespace -eq $namespace }
    
    if (-not $providerExists) {
        return [PSCustomObject]@{
            ResourceProvider = $Provider
            Region = $NormalizedRegion
            Available = $false
            Error = "Provider not found"
        }
    }

    if ($serviceType) {
        $serviceInfo = $providerExists.ResourceTypes | Where-Object { $_.ResourceTypeName -eq $serviceType }
        if (-not $serviceInfo) {
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = $NormalizedRegion
                Available = $false
                Error = "Service type not found"
            }
        }

        # Check for global service
        $isGlobal = ($serviceInfo.Locations.Count -eq 0) -or 
                    ($serviceInfo.Locations -contains '*') -or 
                    ($serviceInfo.Locations -contains 'global')
        if ($isGlobal) {
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = "Global Service"
                Available = $true
                Error = "Available globally"
            }
        }
        else {
            $isAvailable = Is-ServiceAvailableInRegion -ServiceInfo $serviceInfo -NormalizedRegion $NormalizedRegion
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = $NormalizedRegion
                Available = $isAvailable
                Error = if (-not $isAvailable) { "Not available in region" } else { $null }
            }
        }
    }
    else {
        # This branch handles provider-only checks without a specific service type.
        $isGlobal = $true
        foreach ($resourceType in $providerExists.ResourceTypes) {
            if (-not ($resourceType.ResourceTypeName -in @('privateDnsZones', 'dnszones', 'publicIPPrefixes'))) {
                $locations = @()
                if ($resourceType.Locations) { $locations += $resourceType.Locations }
                if ($resourceType.LocationMappings) { $locations += $resourceType.LocationMappings.PhysicalLocation }
                
                if ($locations.Count -gt 0 -and 
                    -not ($locations -contains '*') -and 
                    -not ($locations -contains 'global')) {
                    $isGlobal = $false
                    break
                }
            }
        }
        
        if ($isGlobal) {
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = "Global Service"
                Available = $true
                Error = "Available globally"
            }
        }
        else {
            $isAvailableResult = $providerExists.ResourceTypes | Where-Object {
                Is-ServiceAvailableInRegion -ServiceInfo $_ -NormalizedRegion $NormalizedRegion
            }
            $isAvailable = ($isAvailableResult.Count -gt 0)
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = $NormalizedRegion
                Available = $isAvailable
                Error = if (-not $isAvailable) { "No service types available in region" } else { $null }
            }
        }
    }
}

# ==============================================================================
# 3. HELPER FUNCTIONS
#    These functions assist the core logic.
# ==============================================================================

function Get-ResourceProviderInfo {
    <#
    .SYNOPSIS
        Splits a provider string into its namespace and service type.

    .PARAMETER ProviderString
        The full provider string (e.g., "microsoft.compute/virtualmachines").
    #>
    param (
        [string]$ProviderString
    )
    $providerParts = $ProviderString.Trim() -split '/'
    $normalizedProvider = $providerParts[0].Trim()
    $serviceType = if ($providerParts.Count -gt 1) { $providerParts[1].Trim() } else { $null }
    
    return [PSCustomObject]@{
        Namespace = $normalizedProvider
        ServiceType = $serviceType
    }
}

function Is-ServiceAvailableInRegion {
    <#
    .SYNOPSIS
        Checks if a specific service type is available in a given region.

    .DESCRIPTION
        Compares the provided region against the list of available locations for
        a resource type.

    .PARAMETER ServiceInfo
        The object containing service location information.

    .PARAMETER NormalizedRegion
        The normalized region name to check.
    #>
    param (
        [PSObject]$ServiceInfo,
        [string]$NormalizedRegion
    )
    $locations = @()
    if ($ServiceInfo.Locations) { $locations += $ServiceInfo.Locations }
    if ($ServiceInfo.LocationMappings) { $locations += $ServiceInfo.LocationMappings.PhysicalLocation }
    
    $normalizedLocations = $locations | ForEach-Object { $_.ToLower().Replace(' ', '') }
    $checkRegion = $NormalizedRegion.ToLower().Replace(' ', '')
    
    return $normalizedLocations -contains $checkRegion -or $locations -contains '*'
}

# ==============================================================================
# 4. UTILITY & UI FUNCTIONS
#    These functions handle user interaction and output formatting.
# ==============================================================================

function Show-Banner {
    # Displays a welcome banner.
    $banner = @"
    
    ╔═══════════════════════════════════════════════════════════════╗
    ║           Azure Resource Provider Availability Check          ║
    ╚═══════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-AzureLogin {
    # Tests if the user is logged into Azure and offers to change subscriptions.
    try {
        $context = (Get-AzContext)
        if (-not $context) {
            Write-Host "You are not logged into Azure. Attempting to log in..." -ForegroundColor Yellow
            Connect-AzAccount
        }
        else {
            Write-Host "Already logged into Azure as " -NoNewline
            Write-Host $context.Account -ForegroundColor Green
            Write-Host "Subscription: " -NoNewline
            Write-Host $context.Subscription.Name -ForegroundColor Cyan
            
            $change = Read-Host "`nWould you like to change subscription? (y/N)"
            if ($change -eq 'y' -or $change -eq 'Y') {
                Select-AzureSubscription
            }
        }
    }
    catch {
        Write-Error "Error checking Azure login status: $_"
        exit 1
    }
}

function Select-AzureSubscription {
    # Allows the user to select an Azure subscription from a list.
    try {
        $currentSub = (Get-AzContext).Subscription
        $subs = Get-AzSubscription | Sort-Object Name

        if ($subs.Count -eq 0) {
            Write-Warning "No subscriptions found for this account."
            return $false
        }

        Write-Host "`nAvailable Subscriptions:" -ForegroundColor Yellow
        Write-Host "═════════════════════" -ForegroundColor Yellow
        
        $menuItems = @()
        for ($i = 0 -lt $subs.Count; $i++) {
            $sub = $subs[$i]
            $selected = if ($sub.Id -eq $currentSub.Id) { "* " } else { "  " }
            Write-Host ("{0}[{1}] {2} ({3})" -f $selected, ($i + 1), $sub.Name, $sub.Id) -ForegroundColor $(if ($sub.Id -eq $currentSub.Id) { "Green" } else { "Gray" })
            $menuItems += $sub
        }

        Write-Host "`nCurrent subscription: " -NoNewline
        Write-Host $currentSub.Name -ForegroundColor Green
        $choice = Read-Host "`nEnter number to change subscription (or press Enter to keep current)"

        if (![string]::IsNullOrWhiteSpace($choice)) {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $subs.Count) {
                $newSub = $menuItems[$index]
                Write-Host "Changing to subscription: " -NoNewline
                Write-Host $newSub.Name -ForegroundColor Yellow
                Set-AzContext -Subscription $newSub.Id | Out-Null
                return $true
            }
        }
        return $false
    }
    catch {
        Write-Error "Error changing subscription: $_"
        return $false
    }
}

function Format-OutputTable {
    <#
    .SYNOPSIS
        Formats and displays the results of the availability checks.

    .DESCRIPTION
        This function takes the results from the provider and SKU checks,
        applies color coding for readability, and outputs them in two tables.

    .PARAMETER ProviderResults
        The collection of results from the resource provider check.

    .PARAMETER SkuResults
        The collection of results from the VM SKU check.

    .PARAMETER Region
        The region that was checked.
    #>
    param (
        [PSCustomObject]$ProviderResults,
        [PSCustomObject]$SkuResults,
        [string]$Region
    )
    
    # Define colors for output
    $greenText = "`e[32m"
    $redText = "`e[31m"
    $yellowText = "`e[33m"
    $resetText = "`e[0m"

    # --- Output Resource Provider Table ---
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Resource Provider Availability Results for '$Region'" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    $providerResults | ForEach-Object {
        $isAvailable = $_.Available
        $availableText = if ($isAvailable -is [bool]) {
            if ($isAvailable) { "$greenText True $resetText" } else { "$redText False $resetText" }
        } else {
            $isAvailable
        }
        $errorText = if ($_.Error) { "$yellowText$($_.Error)$resetText" } else { "" }
        
        [PSCustomObject]@{
            ResourceProvider = $_.ResourceProvider
            Region = $_.Region
            Available = $availableText
            Error = $errorText
        }
    } | Format-Table -AutoSize -Wrap

    # --- Output VM SKU Table ---
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "VM SKU Availability & Quota Results for '$Region'" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $skuResults | ForEach-Object {
        $isAvailable = $_.Available
        $availableText = if ($isAvailable -is [bool]) {
            if ($isAvailable) { "$greenText True $resetText" } else { "$redText False $resetText" }
        } else {
            $isAvailable
        }
        
        $delta = $_.Delta
        $deltaText = if ($delta -ne $null -and $delta -lt 0) {
            "$redText$delta$resetText"
        } elseif ($delta -ne $null -and $delta -ge 0) {
            "$greenText$delta$resetText"
        } else {
            "N/A"
        }
        
        $errorText = if ($_.Error) { "$yellowText$($_.Error)$resetText" } else { "" }
        
        [PSCustomObject]@{
            Workload = $_.Workload
            SKU = $_.SKU
            Region = $_.Region
            Available = $availableText
            "Quota Available" = $_."Quota Available"
            "Used Cores" = $_."Used Cores"
            "Required Cores" = $_."Required Cores"
            "Available Cores" = $deltaText
            Error = $errorText
        }
    } | Format-Table -AutoSize -Wrap
    
    # Display summary
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "════════" -ForegroundColor Yellow
    Write-Host "Total Resource Providers Checked: " -NoNewline
    Write-Host $ProviderResults.Count -ForegroundColor Cyan
    Write-Host "Total VM SKUs Checked: " -NoNewline
    Write-Host $SkuResults.Count -ForegroundColor Cyan
    Write-Host ""
}

# ==============================================================================
# 5. MAIN SCRIPT EXECUTION
# ==============================================================================

try {
    # Check that required modules are installed and loaded before running any cmdlets
    foreach ($module in $global:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Error "Required Az PowerShell module '$module' is not installed. Please install it with: Install-Module -Name Az -Scope CurrentUser"
            exit 1
        }
        if (-not (Get-Module -Name $module)) {
            Write-Host "Loading module '$module'..." -ForegroundColor Green
            Import-Module $module -ErrorAction Stop
        } else {
            Write-Host "Module '$module' is already loaded." -ForegroundColor Green
        }
    }

    Show-Banner
    Test-AzureLogin

    Write-Host "`nResource Provider and VM SKU Availability Checker" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Will check availability for $($global:ResourceProvidersToCheck.Count) resource providers and $($global:SKUsToCheck.Count) VM SKUs`n" -ForegroundColor Gray

    Write-Host "Target Region:" -ForegroundColor Yellow
    Write-Host "═════════════" -ForegroundColor Yellow
    $region = Read-Host "Enter region to check (e.g., westus2)"

    Write-Host "`nProcessing Requests..." -ForegroundColor Cyan
    # Execute the main function
    Test-AzureAvailability -ResourceProviders $global:ResourceProvidersToCheck -Region $region
}
catch {
    Write-Error "Script execution failed: $_"
}
exit 1
