param (
    [string]$CatalogName,
    [string]$TenantId,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$CatalogResourceGroup,
    [string]$StorageBlobName = $ResourceGroup + "adcblob",
    [string]$AdlsGen2Name = $ResourceGroup + "adcadls",
    [string]$DataFactoryName = $ResourceGroup + "adcfactory",
    [switch]$ConnectToAzure = $false
)

    .\demoscript.ps1 .\demoscript.ps1 -ConnectToAzure `
                -SubscriptionId $SubscriptionId `
                -TenantId $TenantId

    Write-Host "Creating Azure Resource Group for Purview Account...."
    New-AzResourceGroup `
        -Name $CatalogResourceGroup `
        -Location "East US"
        
    Write-Host "Creating Purview Account...."
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
