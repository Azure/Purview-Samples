param (
    [Parameter(Mandatory=$true)]
    [string]$CatalogName,
    [Parameter(Mandatory=$true)]
    [string]$Location,
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [string]$CatalogResourceGroup,
    [string]$StorageBlobName = $ResourceGroup + "adcblob",
    [string]$AdlsGen2Name = $ResourceGroup + "adcadls",
    [string]$DataFactoryName = $ResourceGroup + "adcfactory",
    [switch]$ConnectToAzure = $false
)

    .\demoscript.ps1 .\demoscript.ps1 -ConnectToAzure `
                -SubscriptionId $SubscriptionId `
                -TenantId $TenantId

    Write-Host "Creating Azure Resource Group for Purview Account.... [ " $CatalogResourceGroup " ] "
    New-AzResourceGroup `
        -Name $CatalogResourceGroup `
        -Location $Location
        
    $PurviewTemplate = Get-Content -Path .\purview_template.json
    $PurviewTemplate -replace 'PURVIEW_ACCOUNT_NAME_CHANGE_BEFORE_RUNNING', $CatalogName | Set-Content -Path .\purview_template.json
    
    Write-Host "Creating Purview Account.... [ " $CatalogName " ] "
    New-AzResourceGroupDeployment `
		-ResourceGroupName $CatalogResourceGroup `
		-TemplateFile .\purview_template.json

    .\demoscript.ps1 -CreateAdfAccountIfNotExists `
		-UpdateAdfAccountTags `
		-DatafactoryAccountName $DataFactoryName `
		-DatafactoryResourceGroup $ResourceGroup `
		-CatalogName $CatalogName `
		-GenerateDataForAzureStorage `
		-GenerateDataForAzureStoragetemp `
		-AzureStorageAccountName $StorageBlobName `
		-CreateAzureStorageAccount `
		-CreateAzureStorageGen2Account `
		-AzureStorageGen2AccountName $AdlsGen2Name `
		-CopyDataFromAzureStorageToGen2 `
		-TenantId $TenantId `
		-SubscriptionId $SubscriptionId `
		-AzureStorageResourceGroup $ResourceGroup `
		-AzureStorageGen2ResourceGroup $ResourceGroup `
		-CatalogResourceGroup $CatalogResourceGroup
