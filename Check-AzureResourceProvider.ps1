function Select-AzureSubscription {
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

function Test-AzureLogin {
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

function Test-ResourceProvider {
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

    # Get all resource providers
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
            # Split provider and service type
            $providerParts = $provider.Trim() -split '/'
            $normalizedProvider = $providerParts[0].Trim()
            $serviceType = if ($providerParts.Count -gt 1) { $providerParts[1].Trim() } else { $null }
            
            # Check if provider exists
            $providerInfo = $availableProviders | Where-Object { $_.ProviderNamespace -eq $normalizedProvider }
            
            if (-not $providerInfo) {
                $results += [PSCustomObject]@{
                    ResourceProvider = $provider
                    Region = $normalizedRegion
                    Available = $false
                    Error = "Provider not found"
                }
                continue
            }

            # If service type is specified, validate it exists
            if ($serviceType) {
                $serviceInfo = $providerInfo.ResourceTypes | Where-Object { $_.ResourceTypeName -eq $serviceType }
                if (-not $serviceInfo) {
                    $results += [PSCustomObject]@{
                        ResourceProvider = $provider
                        Region = $normalizedRegion
                        Available = $false
                        Error = "Service type not found"
                    }
                    continue
                }

                # Enhanced global service detection
                $locations = @()
                if ($serviceInfo.Locations) { $locations += $serviceInfo.Locations }
                if ($serviceInfo.LocationMappings) { $locations += $serviceInfo.LocationMappings.PhysicalLocation }
                
                # More comprehensive global service check
                $isGlobal = $false
                if ($locations.Count -eq 0 -or 
                    $locations -contains '*' -or 
                    $locations -contains 'global' -or
                    ($locations | Where-Object { $_ -ne $null } | Measure-Object).Count -eq 0 -or
                    ($serviceInfo.ResourceTypeName -in @('privateDnsZones', 'dnszones', 'publicIPPrefixes'))) {
                    $isGlobal = $true
                }

                if ($isGlobal) {
                    $results += [PSCustomObject]@{
                        ResourceProvider = $provider
                        Region = "Global Service"
                        Available = $true
                        Error = "Available globally"
                    }
                }
                else {
                    # For regional services
                    $normalizedLocations = $locations | ForEach-Object { $_.ToLower().Replace(' ', '') }
                    $checkRegion = $normalizedRegion.ToLower().Replace(' ', '')
                    
                    $isAvailable = $normalizedLocations -contains $checkRegion
                    $results += [PSCustomObject]@{
                        ResourceProvider = $provider
                        Region = $normalizedRegion
                        Available = $isAvailable
                        Error = if (-not $isAvailable) { "Not available in region" } else { $null }
                    }
                }
            }
            else {
                # For provider-only checks
                $isGlobal = $true

                # Check if any resource type under the provider is regional
                foreach ($resourceType in $providerInfo.ResourceTypes) {
                    $locations = @()
                    if ($resourceType.Locations) { $locations += $resourceType.Locations }
                    if ($resourceType.LocationMappings) { $locations += $resourceType.LocationMappings.PhysicalLocation }

                    # Skip known global services
                    if ($resourceType.ResourceTypeName -in @('privateDnsZones', 'dnszones', 'publicIPPrefixes')) {
                        continue
                    }

                    if ($locations.Count -gt 0 -and 
                        -not ($locations -contains '*') -and 
                        -not ($locations -contains 'global')) {
                        $isGlobal = $false
                        break
                    }
                }

                if ($isGlobal) {
                    $results += [PSCustomObject]@{
                        ResourceProvider = $normalizedProvider
                        Region = "Global Service"
                        Available = $true
                        Error = "Available globally"
                    }
                }
                else {
                    # Check region availability for provider (existing code)
                    $regionInfo = $providerInfo.ResourceTypes | ForEach-Object {
                        $resourceType = $_
                        # Some providers use Location, others use LocationMappings
                        $locations = @()
                        if ($resourceType.Locations) {
                            $locations += $resourceType.Locations
                        }
                        if ($resourceType.LocationMappings) {
                            $locations += $resourceType.LocationMappings.PhysicalLocation
                        }
                        
                        # Normalize location names for comparison
                        $normalizedLocations = $locations | ForEach-Object { $_.ToLower().Replace(' ', '') }
                        $checkRegion = $normalizedRegion.ToLower().Replace(' ', '')
                        
                        if ($normalizedLocations -contains $checkRegion -or $locations -contains '*') {
                            return $_
                        }
                    } | Select-Object -First 1

                    $isGlobal = $locations -contains '*' -or ($locations.Count -eq 0)
                    
                    $results += [PSCustomObject]@{
                        ResourceProvider = $normalizedProvider
                        Region = if ($isGlobal) { "global" } else { $normalizedRegion }
                        Available = $regionInfo -ne $null -or $isGlobal
                        Error = if ($isGlobal) { 
                            "Available globally" 
                        } elseif (-not $regionInfo) { 
                            "Not available in region" 
                        } else { 
                            $null 
                        }
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
    
    # Calculate statistics
    $availableCount = ($results | Where-Object { $_.Available }).Count
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
    Write-Host ($totalProviders - $availableCount) -ForegroundColor Red
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
