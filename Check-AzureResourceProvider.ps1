# This script checks the availability of a predefined list of Azure resource providers in a specified region.
# It requires the Az PowerShell module to be installed.
# It is designed to be self-contained and easy to use.

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
        for ($i = $i -lt $subs.Count; $i++) {
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

function Test-AzureLogin {
    # Tests if the user is logged into Azure and offers to change subscriptions.
    try {
        $context = Get-AzContext
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

function Show-Banner {
    # Displays a welcome banner.
    $banner = @"
    
    ╔═══════════════════════════════════════════════════════════════╗
    ║           Azure Resource Provider Availability Check          ║
    ╚═══════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

# Define the resource providers to check
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
    "microsoft.web/sites"
)

# New helper functions for modularity

function Get-ResourceProviderInfo {
    # Splits a provider string into its namespace and service type.
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
    # Checks if a specific service type is available in a given region.
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

function Determine-ProviderAvailability {
    # Determines the availability of a resource provider in a region.
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
        # Provider-only check (no service type specified)
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
            # This logic can be refined for more precise provider-level checks.
            # For simplicity, we check if at least one service is available in the region.
            $isAvailable = $providerExists.ResourceTypes | Where-Object {
                Is-ServiceAvailableInRegion -ServiceInfo $_ -NormalizedRegion $NormalizedRegion
            }
            return [PSCustomObject]@{
                ResourceProvider = $Provider
                Region = $NormalizedRegion
                Available = $isAvailable -ne $null
                Error = if ($isAvailable -eq $null) { "No service types available in region" } else { $null }
            }
        }
    }
}

function Test-ResourceProvider {
    # The main function to test resource provider availability.
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ResourceProviders,
        
        [Parameter(Mandatory = $true)]
        [string]$Region
    )
    
    # Create array to store results
    $results = @()
    $totalProviders = $ResourceProviders.Count
    $currentProvider = 0

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

    # Get all resource providers once to improve performance
    try {
        $availableProviders = Get-AzResourceProvider
    }
    catch {
        Write-Error "Error fetching resource providers: $_"
        return
    }

    foreach ($provider in $ResourceProviders) {
        $currentProvider++
        Write-Progress -Activity "Checking Resource Providers" -Status "Processing $provider" `
            -PercentComplete (($currentProvider / $totalProviders) * 100)

        try {
            # Use the new modular functions
            $result = Determine-ProviderAvailability -Provider $provider -NormalizedRegion $normalizedRegion -AvailableProviders $availableProviders
            $results += $result

            # Check for Data Lake Gen 2 availability based on the parent provider's status
            if ($provider -eq "microsoft.storage/storageaccounts") {
                if ($result.Available -and $result.Region -ne "Global Service") {
                    # Only add the child result if the parent is available in the region
                    $results += [PSCustomObject]@{
                        ResourceProvider = "$provider/datalakegen2"
                        Region = $normalizedRegion
                        Available = $true
                        Error = "Data Lake Gen 2 supported"
                    }
                } else {
                    # If parent provider is not available, the child is also not available
                    $results += [PSCustomObject]@{
                        ResourceProvider = "$provider/datalakegen2"
                        Region = $normalizedRegion
                        Available = $false
                        Error = "Parent provider 'microsoft.storage/storageaccounts' not available"
                    }
                }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                ResourceProvider = $provider
                Region = $normalizedRegion
                Available = $false
                Error = $_.Exception.Message
            }
        }
    }

    # Display results summary and table
    Write-Host "`n═══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Resource Provider Availability Results" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════`n" -ForegroundColor Cyan
    
    # Define colors for output
    $greenText = "`e[32m"
    $redText = "`e[31m"
    $resetText = "`e[0m"

    # Calculate statistics based on the final results array
    $availableCount = ($results | Where-Object { $_.Available }).Count
    $totalResults = $results.Count
    $globalCount = ($results | Where-Object { $_.Region -eq "Global Service" }).Count
    
    $results | ForEach-Object {
        $availableText = if ($_.Available) {
            "$greenText$($_.Available)$resetText"
        } else {
            "$redText$($_.Available)$resetText"
        }
        
        [PSCustomObject]@{
            ResourceProvider = $_.ResourceProvider
            Region = $_.Region
            Available = $availableText
            Error = $_.Error
        }
    } | Format-Table -AutoSize -Wrap

    # Display summary
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "════════" -ForegroundColor Yellow
    Write-Host "Total Providers Checked: " -NoNewline
    Write-Host $totalProviders -ForegroundColor Cyan
    Write-Host "Available in Region/Globally: " -NoNewline
    Write-Host $availableCount -ForegroundColor Green
    Write-Host "Global Services: " -NoNewline
    Write-Host $globalCount -ForegroundColor Cyan
    Write-Host "Not Available: " -NoNewline
    Write-Host ($totalProviders - ($availableCount - ($results | Where-Object {$_.ResourceProvider -like "*/datalakegen2"}).Count)) -ForegroundColor Red
    Write-Host ""

    # Clear the progress bar
    Write-Progress -Activity "Checking Resource Providers" -Completed

    return $null
}

# Main script execution
try {
    Show-Banner
    Test-AzureLogin

    Write-Host "`nResource Provider Availability Checker" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Will check availability for $($ResourceProvidersToCheck.Count) resource providers`n" -ForegroundColor Gray

    Write-Host "Target Region:" -ForegroundColor Yellow
    Write-Host "═════════════" -ForegroundColor Yellow
    $region = Read-Host "Enter region to check (e.g., westus2)"

    Write-Host "`nProcessing Requests..." -ForegroundColor Cyan
    # Execute the check
    Test-ResourceProvider -ResourceProviders $ResourceProvidersToCheck -Region $region
}
catch {
    Write-Error "Script execution failed: $_"
}
exit 1
