<#
.SYNOPSIS
    Checks the availability of specified Azure resource providers and VM SKUs in a given Azure region, including core quota checks for VM families.

.DESCRIPTION
    This script verifies that required Az PowerShell modules are installed, prompts the user to log in or select a subscription, and checks if a list of predefined resource providers and VM SKUs are available in a specified region. For VM SKUs, it also checks the core quota limits and usage to determine if there are enough cores available for a given workload.

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

# List of Azure resource providers to check.
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
    "microsoft.databricks",
    "Microsoft.ContainerService",
    "Microsoft.Security"
)

# List of VM SKUs to check, including the associated workload and required cores.
$global:VmSkusToCheck = @(
    @{ SKUName = "Standard_D8as_v6"; Cores = 8; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D4as_v6"; Cores = 4; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D8as_v5"; Cores = 8; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D4as_v5"; Cores = 4; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D8as_v4"; Cores = 8; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D4as_v4"; Cores = 4; ResourceType = "virtualMachines"; Workload = "AKS node pools" },
    @{ SKUName = "Standard_D2ds_v4"; Cores = 2; ResourceType = "MySqlFlexibleServers"; Workload = "MySQL DB" },
    @{ SKUName = "Standard_D4as_v6"; Cores = 4; ResourceType = "virtualMachines"; Workload = "Kafka VM" },
    @{ SKUName = "Standard_D8as_v5"; Cores = 8; ResourceType = "virtualMachines"; Workload = "Kafka VM" },
    @{ SKUName = "Standard_B8ms"; Cores = 8; ResourceType = "virtualMachines"; Workload = "Jenkins Agent VM" }
)

# Required PowerShell modules for this script.
$global:RequiredAzModules = @("Az.Accounts", "Az.Compute", "Az.Resources", "Az.Quota")

# Logging configuration
$global:LogFilePath = Join-Path $PSScriptRoot "AzureCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$global:MaxRetries = 3
$global:RetryWaitSeconds = 10

# Caching variables for performance
$global:CachedComputeSkus = $null
$global:CachedQuotas = @{}

# Write a message to both log file and console
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    Add-Content -Path $global:LogFilePath -Value $logMessage
    if ($Level -eq "Error") {
        Write-Host $logMessage -ForegroundColor Red
    } elseif ($Level -eq "Warning") {
        Write-Host $logMessage -ForegroundColor Yellow
    } elseif ($Level -eq "Success") {
        Write-Host $logMessage -ForegroundColor Green
    } else {
        Write-Host $logMessage
    }
}

# ==============================================================================
# 2. CORE FUNCTIONS
# ==============================================================================

# Main function to test resource provider and SKU availability
function Test-AzureAvailability {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ResourceProviders,
        [Parameter(Mandatory = $true)]
        [string]$Region
    )
    Write-Log "Starting Azure availability check for region: $Region"
    $providerResults = @()

    # Validate and normalize region name
    try {
        $allLocations = Get-AzLocation
        Write-Log "Fetched Azure locations."
        $matchedRegion = $allLocations | Where-Object { $_.Location -eq $Region -or $_.DisplayName -eq $Region }
        if (-not $matchedRegion) {
            Write-Log "Invalid region '$Region' entered." "Error"
            Write-Error "Invalid region '$Region'. Valid regions are:"
            $allLocations | Select-Object Location, DisplayName | Format-Table
            return
        }
        $normalizedRegion = $matchedRegion.Location
        Write-Log "Normalized region: $normalizedRegion"
    } catch {
        Write-Log "Error validating region: $_" "Error"
        Write-Error "Error validating region: $_"
        return
    }

    # Get region availability zone info
    try {
        $regionZoneInfo = Get-RegionZoneInfo -Region $normalizedRegion
        Write-Log "Fetched region zone info for $normalizedRegion"
    } catch {
        Write-Log "Failed to determine region zone info: $_" "Warning"
        $regionZoneInfo = [PSCustomObject]@{ SupportsZones = $false; ZoneCount = 0; Zones = @() }
    }

    # Ensure Microsoft.Quota provider is registered
    $quotaProviderStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.Quota -ErrorAction SilentlyContinue
    if ($null -eq $quotaProviderStatus -or $quotaProviderStatus.RegistrationState -ne "Registered") {
        Write-Log "Registering Microsoft.Quota resource provider..."
        Write-Host "`nRegistering Microsoft.Quota resource provider...`n" -ForegroundColor Yellow
        Register-AzResourceProvider -ProviderNamespace Microsoft.Quota -ErrorAction Stop
        $timeout = New-TimeSpan -Minutes 5
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $isRegistered = $false
        do {
            Write-Log "Checking registration status for Microsoft.Quota..."
            Write-Host "Checking registration status... Waiting for Microsoft.Quota to be Registered." -ForegroundColor Gray
            $providerStatus = Get-AzResourceProvider -ProviderNamespace Microsoft.Quota
            if ($providerStatus.RegistrationState -eq "Registered") {
                $isRegistered = $true
                Write-Log "Microsoft.Quota is now registered." "Success"
                Write-Host "`nMicrosoft.Quota is now registered." -ForegroundColor Green
            } else {
                Start-Sleep -Seconds 10
            }
        } while (-not $isRegistered -and $stopwatch.Elapsed -lt $timeout)
        if (-not $isRegistered) {
            Write-Log "Failed to register Microsoft.Quota provider within the timeout period." "Error"
            Write-Error "Failed to register Microsoft.Quota provider within the timeout period."
            return
        }
    } else {
        Write-Log "Microsoft.Quota is already registered. Skipping registration step." "Success"
        Write-Host "`nMicrosoft.Quota is already registered. Skipping registration step." -ForegroundColor Green
    }

    # Get all resource providers once for performance
    try {
        $availableProviders = Get-AzResourceProvider
        Write-Log "Fetched all resource providers."
    } catch {
        Write-Log "Error fetching resource providers: $_" "Error"
        Write-Error "Error fetching resource providers: $_"
        return
    }

    Write-Log "Checking resource provider availability for $($ResourceProviders.Count) providers."
    Write-Host "`nChecking Resource Providers..." -ForegroundColor Cyan
    $totalProviders = $ResourceProviders.Count
    $currentProvider = 0
    foreach ($provider in $ResourceProviders) {
        $currentProvider++
        Write-Progress -Activity "Checking Resource Providers" -Status "Processing $provider" `
            -PercentComplete (($currentProvider / $totalProviders) * 100)
        Write-Log "Checking provider: $provider"
        try {
            $result = Determine-ProviderAvailability -Provider $provider -NormalizedRegion $normalizedRegion -AvailableProviders $availableProviders
            $providerResults += $result
            Write-Log "Provider check result: $($result.Available) for $provider"
        } catch {
            Write-Log "Error checking provider $provider : $_" "Error"
            $providerResults += [PSCustomObject]@{
                ResourceProvider = $provider
                Region = $normalizedRegion
                Available = $false
                Error = $_.Exception.Message
            }
        }
    }
    Write-Progress -Activity "Checking Resource Providers" -Completed

    Write-Log "Checking VM SKU availability."
    $skuResults = Test-SkuAvailability -Region $normalizedRegion

    Write-Log "Formatting output table."
    Format-OutputTable -ProviderResults $providerResults -SkuResults $skuResults -Region $normalizedRegion -RegionZoneInfo $regionZoneInfo
    Write-Log "Azure availability check completed for region: $Region" "Success"
}

# Helper: Determine if a SKU is truly available in a region/zone, considering Restrictions
function Test-SkuZoneAvailability {
    param(
        [object]$SkuFound,
        [string]$Region
    )
    # Get all zones for this SKU in the region
    $zones = @()
    if ($SkuFound.LocationInfo) {
        foreach ($loc in $SkuFound.LocationInfo) {
            if ($loc.Location -ieq $Region) {
                if ($loc.Zones) { $zones += $loc.Zones }
            }
        }
    }
    $zones = ($zones | Select-Object -Unique) | Where-Object { $_ -ne $null -and $_ -ne "" }

    # Remove zones that are restricted
    $restrictedZones = @()
    if ($SkuFound.Restrictions) {
        foreach ($r in $SkuFound.Restrictions) {
            # Restriction by zone
            if ($r.Zones) { $restrictedZones += $r.Zones }
            if ($r.RestrictionInfo -and $r.RestrictionInfo.Zones) { $restrictedZones += $r.RestrictionInfo.Zones }
            # Restriction by region (all zones)
            if ($r.Type -eq "Location" -or $r.ReasonCode -eq "NotAvailableInRegion") {
                # All zones restricted
                return @()
            }
        }
    }
    $restrictedZones = $restrictedZones | Select-Object -Unique
    $availableZones = $zones | Where-Object { $_ -notin $restrictedZones }
    return $availableZones
}

# Check VM SKU availability and quota
function Test-SkuAvailability {
    param([string]$Region)
    Write-Log "Starting VM SKU availability check for region: $Region"
    Write-Progress -Activity "Checking VM Sizes and Quota" -Completed

    $subscriptionId = (Get-AzContext).Subscription.Id
    $quotaScope = "/subscriptions/$subscriptionId/providers/Microsoft.Compute/locations/$Region"

    if (-not $global:CachedComputeSkus) {
        Write-Log "Fetching compute SKUs for $Region"
        $global:CachedComputeSkus = Get-AzComputeResourceSku -Location $Region -ErrorAction Stop
    }

    $regionZoneInfo = Get-RegionZoneInfo -Region $Region

    $results = foreach ($sku in $global:VmSkusToCheck) {
        try {
            $skuName = $sku.SKUName
            Write-Log "Checking SKU: $skuName"
            $skuFound = $global:CachedComputeSkus | Where-Object { $_.Name -eq $skuName }
            if ($skuFound) {
                $availableZones = Test-SkuZoneAvailability -SkuFound $skuFound -Region $Region
                if (-not $availableZones) { $availableZones = @() }
                $allZones = @()
                if ($skuFound.LocationInfo) {
                    foreach ($loc in $skuFound.LocationInfo) {
                        if ($loc.Location -ieq $Region) {
                            if ($loc.Zones) { $allZones += $loc.Zones }
                        }
                    }
                }
                $allZones = ($allZones | Select-Object -Unique) | Where-Object { $_ -ne $null -and $_ -ne "" }
                if ($allZones.Count -gt 0) {
                    $allZones = Sort-Zones -Zones $allZones
                }
                if ($availableZones.Count -gt 0) {
                    $availableZones = Sort-Zones -Zones $availableZones
                }

                # Determine AZ support classification
                if ($allZones.Count -eq 0) {
                    $azSupport = "None"
                } elseif ($availableZones.Count -eq 0) {
                    $azSupport = "Restricted"
                } elseif ($regionZoneInfo.SupportsZones) {
                    $regionZones = $regionZoneInfo.Zones
                    $missing = $regionZones | Where-Object { $_ -notin $availableZones }
                    if ($missing.Count -eq 0 -and $regionZones.Count -gt 0) {
                        $azSupport = "All"
                    } else {
                        $azSupport = "Some"
                    }
                } else {
                    $azSupport = "SKU reports zones"
                }
                $azZonesText = if ($availableZones.Count -gt 0) { [string]::Join(', ', $availableZones) } else { "N/A" }

                # Compute AZ-specific restrictions and explanations
                $azExplanations = ""
                try {
                    $azExplanations = Get-AZExplanations -RegionZones $regionZoneInfo.Zones -SkuZones $availableZones -Restrictions $skuFound.Restrictions
                } catch {
                    $azExplanations = "Error evaluating AZ explanations"
                }
                if (-not $azExplanations) { $azExplanations = "" }

                $azRestrictions = "None"
                try {
                    $azRestrictions = Get-AZRestrictions -Restrictions $skuFound.Restrictions `
                        -LocationInfo $skuFound.LocationInfo `
                        -Region $Region
                } catch {
                    $azRestrictions = "Error extracting AZ restrictions"
                }

                $restrictionText = "None"
                try {
                    $restrictionText = Format-SkuRestrictions -Restrictions $skuFound.Restrictions
                } catch {
                    $restrictionText = "Error formatting restrictions"
                }

                # Quota check with retry logic
                $quota = $null
                $quotaUsage = $null
                $retryCount = 0
                $skuFamily = $skuFound.Family
                while (-not $quota -and $retryCount -lt $global:MaxRetries) {
                    try {
                        Write-Log "Checking quota for SKU family: $skuFamily"
                        $quota = Get-AzQuota -Scope $quotaScope -ResourceName "$skuFamily" -ErrorAction Stop
                        $quotaUsage = Get-AzQuotaUsage -Scope $quotaScope -Name "$skuFamily" -ErrorAction SilentlyContinue
                        break
                    } catch {
                        $retryCount++
                        Write-Log "Retry $retryCount for quota check on $skuFamily" "Warning"
                        if ($retryCount -lt $global:MaxRetries) {
                            Start-Sleep -Seconds $global:RetryWaitSeconds
                        }
                    }
                }
                $quotaLimit = if ($quota) { $quota.Limit.value } else { 0 }
                $currentUsage = if ($quotaUsage) { $quotaUsage.UsageValue } else { 0 }
                $remainingQuota = $quotaLimit - $currentUsage

                Write-Log "SKU $skuName - AZ Support: $azSupport, Quota: $quotaLimit, Used: $currentUsage, Delta: $remainingQuota"

                [PSCustomObject]@{
                    Workload = $sku.Workload
                    SKU = $skuName
                    Region = $Region
                    Available = ($azSupport -ne "Restricted")
                    "Quota Available" = $quotaLimit
                    "Used Cores" = $currentUsage
                    "Required Cores" = $sku.Cores
                    "Delta" = $remainingQuota
                    "AZ Support" = $azSupport
                    "AZ Zones" = $azZonesText
                    "AZ Explanations" = $azExplanations
                    "AZ Restrictions" = $azRestrictions
                    "Restrictions" = $restrictionText
                    Error = if ($azSupport -eq "Restricted") { "SKU is restricted in all zones for this region" } elseif (-not $quota) { "Unable to retrieve quota information" } else { $null }
                }
            } else {
                Write-Log "SKU $skuName not found in region $Region" "Warning"
                [PSCustomObject]@{
                    Workload = $sku.Workload
                    SKU = $skuName
                    Region = $Region
                    Available = $false
                    "Quota Available" = 0
                    "Used Cores" = 0
                    "Required Cores" = $sku.Cores
                    "Delta" = 0
                    "AZ Support" = "N/A"
                    "AZ Zones" = "N/A"
                    "AZ Explanations" = "N/A"
                    "AZ Restrictions" = "N/A"
                    "Restrictions" = "N/A"
                    Error = "SKU not available in region"
                }
            }
        } catch {
            Write-Log "Error processing SKU $skuName : $_" "Error"
            [PSCustomObject]@{
                Workload = $sku.Workload
                SKU = $skuName
                Region = $Region
                Available = $false
                "Quota Available" = 0
                "Used Cores" = 0
                "Required Cores" = $sku.Cores
                "Delta" = 0
                "AZ Support" = "Error"
                "AZ Zones" = "N/A"
                "AZ Explanations" = "Error"
                "AZ Restrictions" = "Error"
                "Restrictions" = "Error"
                Error = $_.Exception.Message
            }
        }
    }
    Write-Log "Completed VM SKU availability check for region: $Region"
    return $results
}

# Add helper to extract zone-specific restriction details (returns concise string or "None")
function Get-AZRestrictions {
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Restrictions,
        [Parameter(Mandatory = $false)]
        [object]$LocationInfo,
        [Parameter(Mandatory = $false)]
        [string]$Region
    )
    
    $entries = @()
    
    # First check LocationInfo for zone capabilities
    if ($LocationInfo) {
        $locationEntry = $LocationInfo | Where-Object { $_.Location -ieq $Region }
        if ($locationEntry) {
            if ($locationEntry.ZoneDetails) {
                foreach ($zd in $locationEntry.ZoneDetails) {
                    # Check for zone-specific status
                    if ($zd.Zones) {
                        $availableZones = $zd.Zones
                        $entries += ("Available in zones: $([string]::Join(',', $availableZones))")
                    }
                    # Check capabilities
                    if ($zd.Capabilities) {
                        foreach ($cap in $zd.Capabilities) {
                            switch ($cap.Name) {
                                "UnavailableZone" {
                                    $entries += ("Zone ${cap.Value} unavailable for this SKU")
                                }
                                "ZoneDetails" {
                                    if ($cap.Value -match "^NotSelected|NotSupported$") {
                                        $entries += ("Zone support: ${cap.Value}")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Then check explicit restrictions
    if ($Restrictions) {
        foreach ($r in $Restrictions) {
            $restrictedZones = @()
            
            # Get zones from all possible sources
            if ($r.Zones) { $restrictedZones += $r.Zones }
            if ($r.RestrictionInfo.Zones) { $restrictedZones += $r.RestrictionInfo.Zones }
            
            if ($restrictedZones.Count -gt 0) {
                $reason = if ($r.ReasonCode) {
                    switch ($r.ReasonCode) {
                        "NotAvailableForSubscription" { "Not available in subscription" }
                        "NotAvailableInRegion" { "Not available in region" }
                        default { $r.ReasonCode }
                    }
                } elseif ($r.Type) {
                    switch ($r.Type) {
                        "Location" { "Location restricted" }
                        "Zone" { "Zone restricted" }
                        default { $r.Type }
                    }
                } else {
                    "Restricted"
                }
                
                $zoneList = [string]::Join(',', ($restrictedZones | Select-Object -Unique))
                $entries += ("Zones ${zoneList}: ${reason}")  # Fixed: Using ${} for variables
            }
            
            # Check for capacity restrictions
            if ($r.Values) {
                foreach ($v in $r.Values) {
                    if ($v.Name -eq "NotAvailableForZones") {
                        $entries += ("Capacity not available in zones: $([string]::Join(',', $v.Value))")
                    }
                }
            }
        }
    }

    if ($entries.Count -eq 0) { return "None" }
    return ([string]::Join('; ', ($entries | Select-Object -Unique)))
}

# --- NEW HELPER: determine if region supports availability zones and how many ---
function Get-RegionZoneInfo {
    <#
    .SYNOPSIS
        Determines whether a region supports availability zones and returns the count/list.

    .PARAMETER Region
        The normalized region name to inspect (e.g., "westus2").
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Region
    )

    try {
        # Use Get-AzLocation to get region metadata
        $location = Get-AzLocation | Where-Object { $_.Location -ieq $Region }
        $zoneList = @()
        $supportsZones = $false

        if ($location -and $location.Metadata) {
            # Try to get zones from Metadata property
            if ($location.Metadata.Zones) {
                $zoneList = $location.Metadata.Zones
            } elseif ($location.Metadata.ZoneDetails) {
                # Some regions use ZoneDetails
                $zoneList = $location.Metadata.ZoneDetails.Zones
            }
            $zoneList = $zoneList | Where-Object { $_ -ne $null -and $_ -ne "" } | Select-Object -Unique
            $supportsZones = ($zoneList.Count -gt 0)
        }

        # Fallback: If no zones found in metadata, try SKU data as a backup
        if (-not $supportsZones) {
            if (-not $global:CachedComputeSkus) {
                $global:CachedComputeSkus = Get-AzComputeResourceSku -Location $Region -ErrorAction Stop
            }
            $allZones = @()
            foreach ($sku in $global:CachedComputeSkus) {
                if ($sku.LocationInfo) {
                    foreach ($locInfo in $sku.LocationInfo) {
                        if ($locInfo.Location -ieq $Region) {
                            if ($locInfo.Zones) {
                                $allZones += $locInfo.Zones
                            }
                        }
                    }
                }
            }
            $zoneList = ($allZones | Select-Object -Unique) | Where-Object { $_ -ne $null -and $_ -ne "" }
            $supportsZones = ($zoneList.Count -gt 0)
        }

        $sortedZones = Sort-Zones -Zones $zoneList
        $zoneCount = $sortedZones.Count

        return [PSCustomObject]@{
            SupportsZones = $supportsZones
            ZoneCount = $zoneCount
            Zones = $sortedZones
        }
    }
    catch {
        Write-Log "Get-RegionZoneInfo error for region '$Region': $_" -Level "Warning"
        return [PSCustomObject]@{
            SupportsZones = $false
            ZoneCount = 0
            Zones = @()
        }
    }
}

# ==============================================================================
# 3. HELPER FUNCTIONS
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

# Helper to determine if a resource provider/service is available in a region
function Determine-ProviderAvailability {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Provider,
        [Parameter(Mandatory = $true)]
        [string]$NormalizedRegion,
        [Parameter(Mandatory = $true)]
        [object[]]$AvailableProviders
    )
    $info = Get-ResourceProviderInfo -ProviderString $Provider
    $namespace = $info.Namespace
    $serviceType = $info.ServiceType

    $providerObj = $AvailableProviders | Where-Object { $_.ProviderNamespace -ieq $namespace }
    if (-not $providerObj) {
        return [PSCustomObject]@{
            ResourceProvider = $Provider
            Region = $NormalizedRegion
            Available = $false
            Error = "Provider namespace not found"
        }
    }

    # Helper to check if a resource type is global
    function Is-GlobalResourceType($resourceTypeObj) {
        if ($null -eq $resourceTypeObj -or -not $resourceTypeObj.Locations) { return $false }
        $locations = $resourceTypeObj.Locations | ForEach-Object { $_.ToLower() }
        # If only "global" or "global" and "*" are present, treat as global
        return ($locations -contains "global" -and ($locations | Where-Object { $_ -ne "global" -and $_ -ne "*" }).Count -eq 0)
    }

    if ($serviceType) {
        $resourceType = $providerObj.ResourceTypes | Where-Object { $_.ResourceTypeName -ieq $serviceType }
        if (-not $resourceType) {
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = $NormalizedRegion
                Available = $false
                Error = "Resource type not found in provider"
            }
        }
        if (Is-GlobalResourceType $resourceType) {
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = "Global Service"
                Available = $true
                Error = $null
            }
        }
        $isAvailable = Is-ServiceAvailableInRegion -ServiceInfo $resourceType -NormalizedRegion $NormalizedRegion
        return [PSCustomObject]@{
            ResourceProvider = $Provider
            Region = $NormalizedRegion
            Available = $isAvailable
            Error = $null
        }
    } else {
        # Provider-level check: available if any resource type is available in region
        foreach ($rt in $providerObj.ResourceTypes) {
            if (Is-GlobalResourceType $rt) {
                return [PSCustomObject]@{
                    ResourceProvider = $Provider
                    Region = "Global Service"
                    Available = $true
                    Error = $null
                }
            }
        }
        $anyAvailable = $false
        foreach ($rt in $providerObj.ResourceTypes) {
            if (Is-ServiceAvailableInRegion -ServiceInfo $rt -NormalizedRegion $NormalizedRegion) {
                $anyAvailable = $true
                break
            }
        }
        return [PSCustomObject]@{
            ResourceProvider = $Provider
            Region = $NormalizedRegion
            Available = $anyAvailable
            Error = $null
        }
    }
}

# ==============================================================================
# 4. UTILITY & UI FUNCTIONS
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
        for ($i = 0; $i -lt $subs.Count; $i++) {
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

    .PARAMETER RegionZoneInfo
        The region availability zone information.
    #>
    param (
        [PSCustomObject]$ProviderResults,
        [PSCustomObject]$SkuResults,
        [string]$Region,
        [PSCustomObject]$RegionZoneInfo
    )
    
    # Define colors for output
    $greenText = "`e[32m"
    $redText = "`e[31m"
    $yellowText = "`e[33m"
    $resetText = "`e[0m"

    # --- NEW: display region availability zone summary ---
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Region Availability Zones for '$Region'" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    if ($RegionZoneInfo -and $RegionZoneInfo.SupportsZones) {
        $zonesList = if ($RegionZoneInfo.Zones -and $RegionZoneInfo.Zones.Count -gt 0) { [string]::Join(', ', $RegionZoneInfo.Zones) } else { "N/A" }
        Write-Host ("This region appears to support availability zones. Zones detected: {0}  ( {1} )" -f $RegionZoneInfo.ZoneCount, $zonesList) -ForegroundColor Green
    }
    else {
        Write-Host "This region does NOT appear to support availability zones (no zones detected for compute SKUs)." -ForegroundColor Yellow
    }

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

    # --- Output VM SKU Table with enhanced AZ information ---
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "VM SKU Availability, AZ Support & Quota Results for '$Region'" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    # Group SKUs by AZ support status for better readability
    $groupedSkus = $skuResults | Group-Object -Property { $_."AZ Support" }
    
    foreach ($group in $groupedSkus | Sort-Object { 
        switch($_.Name) {
            "All" { 1 }
            "Some" { 2 }
            "None" { 3 }
            "SKU reports zones" { 4 }
            default { 5 }
        }
    }) {
        $group.Group | ForEach-Object {
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
            } else { "N/A" }
            
            # Color and format AZ-related fields
            $azZonesDisplay = if ($_."AZ Zones" -eq "N/A") { 
                "$yellowText$($_."AZ Zones")$resetText" 
            } else { 
                "$greenText$($_."AZ Zones")$resetText" 
            }

            $azRestrRaw = if ($_.PSObject.Properties.Match('AZ Restrictions').Count -gt 0) { $_."AZ Restrictions" } else { "None" }
            $azRestrDisplay = switch -Regex ($azRestrRaw) {
                '(?i)None|^N/?A$' { "$greenText$azRestrRaw$resetText" }
                '(?i)NotAvailableForSubscription|ZoneRestricted' { "$redText$azRestrRaw$resetText" }
                default { "$yellowText$azRestrRaw$resetText" }
            }

            $errorText = if ($_.Error) { "$yellowText$($_.Error)$resetText" } else { "" }

            [PSCustomObject]@{
                Workload = $_.Workload
                SKU = $_.SKU
                Available = $availableText
                "AZ Zones Available" = $azZonesDisplay
                "AZ Restrictions" = $azRestrDisplay
                "Quota Available" = $_."Quota Available"
                "Used Cores" = $_."Used Cores"
                "Required Cores" = $_."Required Cores"
                "Available Cores" = $deltaText
                Error = $errorText
            }
        } | Format-Table -AutoSize -Wrap
    }

    # Display summary
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "════════" -ForegroundColor Yellow
    Write-Host "Total Resource Providers Checked: " -NoNewline
    Write-Host $ProviderResults.Count -ForegroundColor Cyan
    Write-Host "Total VM SKUs Checked: " -NoNewline
    Write-Host $SkuResults.Count -ForegroundColor Cyan
    Write-Host ""
}

# Helper to sort and deduplicate zone IDs (e.g., ["2","1","3"] => ["1","2","3"])
function Sort-Zones {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Zones
    )
    # Remove null/empty, deduplicate, sort numerically then lexically
    $Zones | Where-Object { $_ -ne $null -and $_ -ne "" } | 
        Select-Object -Unique | 
        Sort-Object { 
            if ($_ -match '^\d+$') { [int]$_ } else { $_ }
        }
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
