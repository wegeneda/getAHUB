

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionID = "",

    [Parameter(Mandatory = $false)]
    [string]$workspaceID = "",

    [Parameter(Mandatory = $false)]
    [string]$workspacename = "",

    [Parameter(Mandatory = $false)]
    [string]$AvailLic = 5

)



#login to azure
#Login-AzAccount

#get bearer token for webrequest
$currentAzureContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
$token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
$accessToken = $token.AccessToken
$authHeader = @{"Authorization" = "BEARER " + $accessToken }

#set up the rest request
function Build-signature ($CustomerID, $SharedKey, $Date, $ContentLength, $method, $ContentType, $resource) {
    $xheaders = 'x-ms-date:' + $Date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.key = $keyBytes
    $calculateHash = $sha256.ComputeHash($bytesToHash)
    $encodeHash = [convert]::ToBase64String($calculateHash)
    $authorization = 'SharedKey {0}:{1}' -f $CustomerID, $encodeHash
    return $authorization
}
#send rest request
function send-data([string]$WorkspaceId, [string]$Workspacename, $logMessage, $authHeader) {
    # get workspace secret
    $dateTime = get-date
    if ($dateTime.kind.tostring() -ne 'Utc') {
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message $dateTime
    }
    $logType = "AHUB_CL"
    $wrkspce = " https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.OperationalInsights/workspaces?api-version=2015-11-01-preview"
    $r = Invoke-WebRequest -Uri $wrkspce -Method GET -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    [string]$wrkspce = $clear.value.id | select-string ("$Workspacename")
    [array]$arr = $wrkspce.split("/")
    $WorkspaceRG = $arr[4]
    $workspacekeyurl = "https://management.azure.com/subscriptions/$subscriptionID/resourcegroups/$WorkspaceRG/providers/Microsoft.OperationalInsights/workspaces/$workspacename/sharedKeys?api-version=2015-11-01-preview"
    $r = Invoke-WebRequest -Uri $workspacekeyurl -Method POST -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    $WorkspaceKey = $clear.primarySharedKey
    $body = ([System.Text.Encoding]::UTF8.GetBytes($logMessage))
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $WorkspaceId `
        -sharedKey $WorkspaceKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $dateTime;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing 
    return $response.StatusCode
}
#create hashtables
$array=@()
$ahubVM=@()
$vmlist = @{}

#Amount of 2-proc licenses / 16 core with SA
$AvailLic = 5

#use resourcegraph to get all vm's with AHUB
$array+=Search-AzGraph -Query "project name, size = properties.hardwareProfile.vmSize, properties.licenseType, properties.licenseType, resourceGroup, subscriptionId, type, properties.storageProfile.osDisk.osType, location  | where type =~ 'Microsoft.Compute/virtualMachines'"
$ahubVM=$array | ? { $_.properties_licenseType -eq "Windows_Server" }


#get vm information
$ahubVM | % {
    $VMname = $_.name
    $Vmlocation = $_.location
    $vmsize = $_.size
    $vmcores = ((Get-AzVMSize -Location $Vmlocation) | ? { $_.name -eq $vmsize }).NumberOfCores
    $vmlist.Add($VMname,$vmcores)
}

#Case1: get all vm's with <= 8 cores
$case1tmp=($vmlist.GetEnumerator().Where({$_.Value -le 8})).count
$case1=$case1tmp / 2

#Case2: get all vm's with >8 and <=16 cores
$case2=($vmlist.GetEnumerator().Where({($_.Value -gt 8) -AND ($_.Value -le 16)})).count

#Case3 get all vm's with >16 cores
$case3lic=@()
$case3=($vmlist.GetEnumerator().Where({$_.Value -gt 16}))
$case3 | % {
    $tmp=$_.Value / 16
    $tmp=[Math]::Ceiling($tmp)
    $case3lic+=$tmp
    
}
$case3=($case3lic | Measure-Object -Sum).Sum

#do the math
$totalLicReq= $case1+$case2+$case3

"$totalLicReq Licenses required"

#output of the total amount of cores from AHUB enabled VM's
#$totalAHUBcores=($vmlist.Values | Measure-Object -Sum).Sum

#do the math
$unused = $AvailLic-$totalLicReq

#format the data
$Result = @"
[{  "TotalconsumedLicenses": "$totalLicReq",
    "AvailableLicenses": $unused
}]
"@

#send information to log analytics
send-data -WorkspaceId $WorkspaceID -Workspacename $Workspacename -logMessage $Result -authHeader $authHeader




