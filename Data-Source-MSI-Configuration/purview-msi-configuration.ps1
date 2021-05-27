<#requires -version 5.1
#requires -RunAsAdministrator
##requires -Module Az#>

<#
.SYNOPSIS
This script is aimed to help organizations verify missing RBAC roles and network access for various Azure Data Sources before registering and scanning Azure data sources in Azure Purview. 

.DESCRIPTION
This PowerShell script is aimed to assist Azure Subscriptions administrators to setup required RBAC and network access for Azure Purview Account to scan resources under a defined list of Azure Subscriptions. 
This version is reduced in prompts during the execution. 

PRE-REQUISITES:
1. If you already have the Az modules installed, you may still encounter the following error:
    The script cannot be run because the following modules that are specified by the "#requires" statements of the script are missing: Az.at line:0 char:0
    To resolve this issue, please run the following command to import the Az modules into your current session:
    Import-Module -Name Az -Verbose

2. An Azure Purview Account.

3. Azure resources such as Storage Accounts, ADLS Gen2 Azure SQL Databases or Azure SQL Managed Instances.

4. Required permissions to run the script and assign the permissions:
    4.1 For BlobStorage: Owner or User Access Administrator on data sources' subscriptions
    4.2 For ADLSGen1 and ADLSGen2: Owner or User Access Administrator on data sources' subscriptions
    4.3 For AzureSQLDB: Read Key Vault and have access to get/list Azure Key Vault secret where Azure SQL Admin credentials are stored.   
    4.4 For AzureSQLMI: Read Key Vault and have access to get/list Azure Key Vault secret where Azure SQL Admin credentials are stored.  
    4.5 For Azure Synapse: Read Key Vault and have access to get/list Azure Key Vault secret where Azure Synapse Admin credentials are stored.
    4.6 Azure AD (at least Global Reader) to read Azure AD users and Groups. If Azure SQL MI Azure AD Authentication is not configured, you need access to update AAD Directory Reader role membership.
    4.7 Azure Contributor role on data sources.

Execute this script by providing the following parameters:
    1. create a csv file (e.g. "C:\Temp\Subscriptions.csv) with 4 columns:
        a. Column name: SubscriptionId
        This column must contain all subscription ids where your data sources reside.
        example: 12345678-aaaa-bbbb-cccc-1234567890ab

        b. Column name: KeyVaultName
        Provide existing key vault name resource that is deployed in the same corresponding data source subscription.
        example: ContosoDevKeyVault

        c. Column name: SecretNameSQLUserName
        Provide existing key vault secret name that contains Azure Synapse / Azure SQL Servers/ SQL MI Azure AD authentication admin username saved in the secret. This user can be added to a group that is configured in Azure AD authentication on Azure SQL Servers.
        example: ContosoDevSQLAdmin

        d. Column name: SecretNameSQLPassword
        Provide existing key vault secret name that contains Azure Synapse / Azure SQL Servers/ SQL MI Azure AD authentication admin password saved in the secret. This user can be added to a group that is configured in Azure AD authentication on Azure SQL Servers.
        example: ContosoDevSQLPassword

        Note: Before running this script update the file name / path further in the code, if needed.

    2. AzureDataType: as data source type, use any of the following options: 
    
        "BlobStorage"
        "AzureSQLMI"
        "AzureSQLDB"
        "ADLSGen2"
        "ADLSGen1"
        "Synapse"
        "All"

    3. PurviewAccount: Your existing Azure Purview Account resource name.

    4. -PurviewSub: Subscription ID where Azure Purview Account is deployed.


.NOTES

CONTRIBUTORS
1. Zeinab Mokhtarian Koorabbasloo zeinam@microsoft.com

LEGAL DISCLAIMER:
This Code is provided for the purpose of assisting organizations to deploy Azure Purview. It should be tested prior using in production environment. Users are responsible for evaluating the impact on production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights.

.LINK

1. https://docs.microsoft.com/en-us/azure/purview/overview
2. https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15 

.COMPONENT
Azure Infrastructure, PowerShell

#>

Param
(
    [ValidateSet("BlobStorage", "AzureSQLMI", "AzureSQLDB", "ADLSGen2", "ADLSGen1", "Synapse", "All")]
    [string] $AzureDataType = "All",
    [string] $PurviewAccount,
    [string] $PurviewSub
)

$ErrorActionPreference = 'Continue'
$WarningPreference ='silentlycontinue'

# Set-StrictMode -Version Latest

<#if (-not($skipAzModules))
{
    #region Az modules
    Install-Module -Name Az -AllowClobber -Verbose
    Import-Module -Name Az    
    #endregion Az modules
} # end if 
#>

#Data source type
<#Select one of the following Azure Data Sources to check readiness:
BlobStorage     for Azure Blob Storage
AzureSQLDB      for Azure SQL Database
AzureSQLMI      for Azure SQL Managed Instance
ADLSGen2        for Azure Data Lake Storage Gen 2
ADLSGen1        for Azure Data Lake Storage Gen 1
Synapse         for Azure Synapse Analytics
All             for all the above data sources 
 #>
Write-Host "'$AzureDataType' is selected as Data Source." -ForegroundColor Magenta


#Clear any possible cached credentials for other subscriptions
Clear-AzContext

#Login to Azure AD 
Write-Host "Please sign in with your Azure AD administrator account:"
Connect-AzureAD

#Authentication to Azure 
Write-Host "Please sign in with your Azure administrator credentials:"
Login-AzAccount

#Purview subscription 
$PurviewSubContext = Set-AzContext -Subscription $PurviewSub 
Write-Host "Subscription: '$($PurviewSubContext.Subscription.Name)' is selected where Azure Purview Account is deployed." -ForegroundColor Magenta

#get Purview account MSI and location
$PurviewAccountMSI = (Get-AzResource -Name $PurviewAccount).Identity.PrincipalId

If ($null -ne $PurviewAccountMSI) {
    Write-Host "Azure Purview Account '$($PurviewAccount)' is selected" -ForegroundColor Magenta
    $Purviewlocation = (Get-AzResource -Name $PurviewAccount).Location
}else {
    Write-Host "There is no Managed Identity for Azure Purview Account '$($PurviewAccount)'! Terminating..." -ForegroundColor red
    Break
}

#Get the CSV file content for input            
$Subscriptions = import-csv -Path "C:\Temp\Subscriptions.csv"            
$SubscriptionCount = $Subscriptions.Count;      
Write-Host ""
Write-Host "$SubscriptionCount Subscriptions are found inside the csv list!"      
$currentSubscription = 1;                     

#If Azure SQL Database (AzureSQLDB) is selected for Azure Data Source
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLDB")) {

    Write-Host ""
    Write-Host "Processing Azure SQL Servers..." -ForegroundColor Magenta
    Write-host ""
       
    foreach($Subscription in $Subscriptions) {
        # Select and process each data source subscription from the csv       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 

        Write-Host "Processing Subscription: '$($DataSubContext.Subscription.Name)'..."  -ForegroundColor Magenta
      
        #get az kv secrets
        $PurviewKV = Get-AzKeyVault -VaultName $Subscription.KeyVaultName
        If ($null -eq $PurviewKV) 
        {
            Write-Host "Key Vault '$($Subscription.KeyVaultName)' Account not found!" -ForegroundColor red
        }else {
            # get sql admin user 
            $AzSQLUserName = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLUserName
            If ($null -eq $AzSQLUserName) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLUserName)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLUserName =  $AzSQLUserName.SecretValue     
            }
            
            #get sql admin password 
            $AzSQLPassword = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLPassword
            If ($null -eq $AzSQLPassword) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLPassword)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLPassword =  $AzSQLPassword.SecretValue
            }            
        }

        $AzureSqlServers = Get-AzSqlServer
        foreach ($AzureSqlServer in $AzureSqlServers) {

            Write-Host "Verifying SQL Server: '$($AzureSqlServer.ServerName)'... " -ForegroundColor Magenta

            #Public and Private endpoint 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSqlServer.ResourceId -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoints: '$($PrivateEndPoints.Name)' is configured on Azure SQL server: '$($AzureSqlServer.ServerName)'."
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure SQL Server: '$($AzureSqlServer.ServerName)', Verifying Firewall Rules...'."
            }    
            If ($AzureSqlServer.PublicNetworkAccess -like 'Enabled') {
                #Public EndPoint enabled
                Write-Output "Awareness! Public Endpoint is allowed on Azure SQL server: '$($AzureSqlServer.ServerName)'."
                $AzureSqlServerFw = Get-AzSqlServerFirewallRule -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName "Rule*"
                if (($AzureSqlServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps") -or ($AzureSqlServerFw.FirewallRuleName -contains "AllowAllAzureIPs"))
                {
                        Write-Output "'Allow Azure services and resources to access this server' is enabled on Azuer SQL Server: '$($AzureSqlServer.ServerName)'. No action is needed." 
                }else {
                    
                    #Azure IPs are not allowed to access Azure SQL Server     
                    Write-host ""
                    Write-host "'Allow Azure services and resources to access this server' is not enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)'! Processing..." -ForegroundColor yellow    
                    New-AzSqlServerFirewallRule -ResourceGroupName $AzureSqlServer.ResourceGroupName -ServerName $AzureSqlServer.ServerName -AllowAllAzureIPs
                    Write-Output "'Allow Azure services and resources to access this server' is now enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)' "        

                }        
            }
                   
            #Verify / Assign Azure AD Admin                   
            $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
            
            # Validate whether the sql admin user account that is provided in csv, actually exists in AAD  
            $AzSQLAADAdminPrompted =  $AzSQLAADAdminPrompted = ([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)
            $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted
            $AzSQLAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSQLAADAdminPrompted.ObjectId  

            If ($null -ne $AzSQLAADAdminConfigured){

                # Azure AD Authentucation is enabled on Azure SQL Server
                Write-Host "Verifying Azure AD Authentication on Azure SQL Server: '$($AzureSqlServer.ServerName)' ..." -ForegroundColor Magenta
                  
            }else {
                        
                # Azure AD Authentucation is not enabled on Azure SQL Server
                Write-Host "Azure AD Authentication is not enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)'! Processing..." -ForegroundColor yellow
                            
                # Set Azure AD Authentication on Azure SQL Server
                Set-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroupName $AzureSqlServer.ResourceGroupName -DisplayName $AzSQLAADAdminPrompted.DisplayName
                Write-Output "Azure AD Authentication is now enabled for user: '$($AzSQLAADAdminPrompted.DisplayName)' on Azure SQL Server: '$($AzureSqlServer.ServerName)'."
                $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName 
      
            }    
            #Assign SQL db_datareader Role to Azure Purview MSI on each Azure SQL Database 
            $AzureSQLDBs = Get-AzSqlDatabase -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
            foreach ($AzureSQLDB in $AzureSQLDBs) {
                if ($AzureSQLDB.DatabaseName -ne "master") {
                                           
                    #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Server
                    If (($AzSQLAADAdminConfigured.DisplayName -eq $AzSQLAADAdminPrompted.DisplayName) -OR ($AzSQLAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLAADAdminConfigured.ObjectId))
                        {
                            sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                            Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSQLDB.DatabaseName)' on Azure SQL Server '$($AzureSqlServer.ServerName)'."

                        }else {    
                            Write-Output "'$($AzSQLAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Server:'$($AzureSqlServer.ServerName)'. '$($AzSQLAADAdminConfigured.DisplayName)' is found as SQL Server Admin on Azure AD Authentication configuration on the server."
                               
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            $AzSQLAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Server Administrator account that is Azure AD Integrated or press Enter to skip"
                            if (!$AzSQLAADAdminPrompted) { 
                                Write-Host "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!" -ForegroundColor Red 
                            }else{
                                $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted
                                sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U $AzSQLAADAdminPrompted.UserPrincipalName -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                                Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSQLDB.DatabaseName)' on Azure SQL Server '$($AzureSqlServer.ServerName)'."
                            }   
                        }
                }             
            } 
                                
            write-host ""
        }  
        Write-host "`n"
        write-host "Readiness deployment completed for Azure SQL Servers in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }  
}

# If Azure SQL Managed Instance (AzureSQLMI) is selected for Azure Data Source
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLMI")) {
    
    Write-Host ""
    Write-Host "Processing Azure SQL Managed Instances ..." -ForegroundColor Magenta 
    Write-Host ""

    foreach($Subscription in $Subscriptions) {
        # Select and process each data source subscription from the csv       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 

        Write-Host "Processing Subscription: '$($DataSubContext.Subscription.Name)'..."  -ForegroundColor Magenta
      
        #get az kv secrets
        $PurviewKV = Get-AzKeyVault -VaultName $Subscription.KeyVaultName
        If ($null -eq $PurviewKV) 
        {
            Write-Host "Key Vault '$($Subscription.KeyVaultName)' Account not found!" -ForegroundColor red
        }else {
            # get sql admin user 
            $AzSQLUserName = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLUserName
            If ($null -eq $AzSQLUserName) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLUserName)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLUserName =  $AzSQLUserName.SecretValue     
            }
            
            #get sql admin password 
            $AzSQLPassword = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLPassword
            If ($null -eq $AzSQLPassword) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLPassword)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLPassword =  $AzSQLPassword.SecretValue
            }
            
        }          
        $AzureSqlMIs = Get-AzSqlInstance
        foreach ($AzureSqlMI in $AzureSqlMIs) {
                      
            #Verify if Public endpoint is enabled                    
            If ($AzureSqlMI.PublicDataEndpointEnabled -like 'False')
            {
                Write-Host "Private endpoint is not yet supported by Azure Purview. Your organization must allow public endpoint in '$($AzureSqlMI.ManagedInstanceName)'.Processing..." -ForegroundColor yellow       
                Set-AzSqlInstance -Name $AzureSqlMI.ManagedInstanceName -ResourceGroupName $AzureSqlMI.ResourceGroupName -PublicDataEndpointEnabled $true -force
                Write-Output "Public endpoint on your Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)' is now enabled."
            }
            
            #Verify and configure NSG Rules
            If ($AzureSqlMI.ProxyOverride = "Redirect") {
                #ProxyOverride is Redirect
                $AzureSQLMIPorts = "11000-11999"
                Write-Host "Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)' is configured as 'Redirect'. Checking ports 11000-11999 and 1433 in NSG rules..."
            }else {
                #ProxyOverride is Proxy (default) 
                $AzureSQLMIPorts = 3342
                Write-Host "Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)' is configured as 'Proxy'. Checking port 3342 in NSG rules..."
            }

            $AzureSqlMISubnet = $AzureSqlMI.SubnetId
            $AzureSqlMISubnet =  Get-AzVirtualNetworkSubnetConfig -ResourceId $AzureSqlMISubnet
            $nsg = $AzureSqlMISubnet.NetworkSecurityGroup
            $nsg = Get-AzResource -ResourceId $NSG.id
            $nsg = Get-AzNetworkSecurityGroup -Name $nsg.Name -ResourceGroupName $nsg.ResourceGroupName
            $NsgRules = $nsg.SecurityRules
            $nsgRuleAllowing = 0
            $Priority = $null
            foreach ($nsgRule in $nsgRules) {
                $Priority += @($NsgRule.Priority) 
                if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                    if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains $AzureSQLMIPorts)) {
                        Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts. No action is needed."
                        $nsgRuleAllowing = 1
                    }else{
                        $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                        foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                            if ($nsgRulePortRange -match "-") {
                                $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                if (($AzureSQLMIPorts -le $nsgRulePortRangeHigh) -and ($AzureSQLMIPorts -ge $nsgRulePortRangeLow)) {
                                    Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts. No action is needed."
                                    $nsgRuleAllowing = 1
                                }
                            }
                        }
                    }		
                }else{
                                  
                }
            }
                  
            if ($nsgRuleAllowing -eq 0) {
                Write-Host "No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts!. Processing..." -ForegroundColor yellow
                $NSGRuleName = "AllowAzureCloudSQLMI"
                $Priority = $Priority.Where({ 100 -le $_ })
                $lowest = $Priority | sort-object | Select-Object -First 1
                Do {
                    $lowest = $lowest + 1
                }
                Until (($lowest -notin $Priority) -and ($lowest -le 4096))

                Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $NSGRuleName -Access Allow -Protocol tcp -Direction Inbound -Priority $lowest -SourceAddressPrefix "AzureCloud" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $AzureSQLMIPorts | Set-AzNetworkSecurityGroup        
                Write-Output "A NSG Rule 'AllowAzureCloudINSQLMI' is added to '$($NSG.Name)'." 
        
            }
                    
            #Checking port 1433
            If ($AzureSqlMI.ProxyOverride = "Redirect") 
            {
                foreach ($nsgRule in $nsgRules) 
                {
                    $Priority += @($NsgRule.Priority) 
                    if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) 
                    {
                        if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains "1433")) {
                            Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433.  No action is needed."
                            $nsgRuleAllowing = 1
                        }else{
                            $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                            foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                if ($nsgRulePortRange -match "-") {
                                                
                                    $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                    if ((1433 -le $nsgRulePortRangeHigh) -and (1433 -ge $nsgRulePortRangeLow)) {
                                        Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through ports 1433. No action is needed."
                                        $nsgRuleAllowing = 1
                                    }
                                }
                            }
                        }		
                    }else{}                                 
                        
                }
                      
                if ($nsgRuleAllowing -eq 0) {
                    Write-Host "No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433!. Processing..." -ForegroundColor yellow

                    $NSGRuleName = "AllowAzureCloud1433"
                    $Priority = $Priority.Where({ 100 -le $_ })
                    $lowest = $Priority | sort-object | Select-Object -First 1
                    Do {
                        $lowest = $lowest + 1
                    }
                    Until (($lowest -notin $Priority) -and ($lowest -le 4096))
                                
                    Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $NSGRuleName -Access Allow -Protocol tcp -Direction Inbound -Priority $lowest -SourceAddressPrefix "AzureCloud" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 1433 | Set-AzNetworkSecurityGroup        
                    Write-Output "A NSG Rule 'AllowAzureCloudINSQLMI' is added to '$($NSG.Name)'." 
                }
            }
            write-host ""
            $AzSQLMIAADAdminPrompted = ([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)
            $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted
            $AzSQLMIAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSQLMIAADAdminPrompted.ObjectId     
            $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
            If ($null -ne $AzSQLMIAADAdminConfigured) {
                
                #AAD Authentication is configured on Azure SQL Managed Instance
                Write-Host "Verifying Azure AD Authentication on Azure SQL Server: '$($AzureSqlMI.ManagedInstanceName)' ..." -ForegroundColor Magenta
                        
            }else {
                # Azure AD Authentucation is not enabled on Azure SQL Managed Instance
                Write-Host "Azure AD Authentication is not enabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'!. Processing..." -ForegroundColor yellow
                
                #Assign Azure Active Directory read permission to a Service Principal representing the SQL Managed Instance.
                $AzureADReader = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq "Directory Readers"}
                $AzureADReaderMember = Get-AzureADServicePrincipal -SearchString $AzureSqlMI.ManagedInstanceName

                if ($null -eq $AzureADReader) {
                    
                    # Instantiate an instance of the role template
                    $AzureADReaderTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object {$_.displayName -eq "Directory Readers"}
                    Enable-AzureADDirectoryRole -RoleTemplateId $AzureADReaderTemplate.ObjectId
                    $AzureADReader = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq "Directory Readers"}
                }

                # Check if service principal is already member of readers role
                $AzureADReaderMembers = Get-AzureADDirectoryRoleMember -ObjectId $AzureADReader.ObjectId
                $selDirReader =$AzureADReaderMembers | where{$_.ObjectId -match $AzureADReaderMember.ObjectId}

                if ($null -eq $selDirReader) {
                    # Add principal to AAD Readers role
                    Write-Host "Adding service principal '$($AzureSqlMI.ManagedInstanceName)' to 'Directory Readers' role'..."
                    Add-AzureADDirectoryRoleMember -ObjectId $AzureADReader.ObjectId -RefObjectId $AzureADReaderMember.ObjectId
                    Write-Output "'$($AzureSqlMI.ManagedInstanceName)' service principal is now added to 'Directory Readers' role'."
                            
                }else {
                    Write-Output "Service principal '$($AzureSqlMI.ManagedInstanceName)' is already member of 'Directory Readers' role'."
                }

                # Set Azure AD Authentication on Azure Managed Instance
                Set-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName -DisplayName $AzSQLMIAADAdminPrompted.UserPrincipalName -ObjectId $AzSQLMIAADAdminPrompted.ObjectId
                Write-Output "Azure AD Authentication is now enabled for user: '$($AzureSqlMI.ManagedInstanceName)' on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)' "
                $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName        
            }
                    
            $AzureSQLMIDBs = Get-AzSqlInstanceDatabase -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName                        
            foreach ($AzureSQLMIDB in $AzureSQLMIDBs) {
                if (($AzureSQLMIDB.Name -ne "master") -or ($AzureSQLMIDB.Name -ne "model") -or ($AzureSQLMIDB.Name -ne "msdb") -or ($AzureSQLMIDB.Name -ne "tempdb")) 
                {
                    $AzureSqlMIFQDN = $AzureSqlMI.ManagedInstanceName + ".public." + $AzureSqlMI.DnsZone +"."+ "database.windows.net,3342"
                    Write-Host "Connecting to '$($AzureSQLMIDB.Name)' on Azure SQL Manage Instance '$($AzureSqlMIFQDN)'..." -ForegroundColor Magenta

                    $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                                
                    #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Managed Instance 
                    If (($AzSQLMIAADAdminConfigured.DisplayName -eq $AzSQLMIAADAdminPrompted.UserPrincipalName) -OR ($AzSQLMIAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLMIAADAdminConfigured.ObjectId))
                    {
                        sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                        Write-Output  "Azure SQL DB: db_datareader role is assigned to $PurviewAccount in '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSQLMIDBs.ManagedInstanceName)'."   

                    }else {
                        Write-Output "'$($AzSQLMIAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)'. '$($AzSQLMIAADAdminConfigured.DisplayName)' is found as SQL Server Admin on Azure AD Authentication configuration on the server."
                        Write-host "Please provide the required information! " -ForegroundColor blue
                        $AzSQLMIAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Managed Instances Administrator account that is Azure AD Integrated or press Enter to skip"

                        if (!$AzSQLMIAADAdminPrompted) { 
                            Write-Host "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Server!" -ForegroundColor Red 
                        }else{
                            $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted
                            sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U $AzSQLMIAADAdminPrompted.UserPrincipalName -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                            Write-Output  "Azure SQL DB: db_datareader role is assigned to $PurviewAccount in '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSQLMIDBs.ManagedInstanceName)'."   
                        }
                    }               
                }
            }
   
        }                
        Write-host "`n"
        write-host "Readiness deployment completed for Azure SQL Managed Instances in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }    
}

# If Azure Storage Account (BlobStorage) or Azure Data Lake Gen 2 (ADLSGen2) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "BlobStorage") -or ($AzureDataType -eq "ADLSGen2"))
{
    Write-Host ""
    Write-Host "Processing Azure Storage ..." -ForegroundColor Magenta 
    Write-Host ""
    foreach($Subscription in $Subscriptions) {
        # Select and process each data source subscription from the csv       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 
        Write-Host "Processing Subscription: '$($DataSubContext.Subscription.Name)'..."  -ForegroundColor Magenta
        Write-Host "Processing RBAC assignments for Azure Purview Account $($PurviewAccount) for $AzureDataType ..." -ForegroundColor Magenta
        $ControlPlaneRole = "Reader"
        $RBACScope = "/subscriptions/" + $DataSubContext.Subscription.SubscriptionId

        #Check if Reader role is assigned            
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $RBACScope
                    
        if (!$ExistingReaderRole) {
            #Assign Reader role to Azure Purview 
            New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $RBACScope
            Write-Output "Azure RBAC 'Reader' role is now assigned to Azure Purview at the selected scope!"
        }else {
            Write-Output "Azure RBAC 'Reader' role is already assigned to Azure Purview at the selected scope. No action is needed." 
        }
                    
        Write-Host ""
        #Verify whether RBAC is already assigned, otherwise assign RBAC
        $Role = "Storage Blob Data Reader"
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                        
        if (!$ExistingRole) {
            New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope  
            Write-Output  "Azure RBAC 'Storage Blob Data Reader' role is now assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'."
        }else {
            Write-Output "Azure RBAC 'Storage Blob Data Reader' role is already assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'. No action is needed." 
        }
            
        # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
                
        # If ADLSGen2
        If ($AzureDataType -eq "ADLSGen2")
        {
            $StorageAccounts = Get-AzStorageAccount | Where-Object {$_.EnableHierarchicalNamespace -eq 'True'}    
        }else{
            $StorageAccounts = Get-AzstorageAccount
        }
        Write-Host ""             
        Write-Host "Verifying your Azure Storage Accounts Networks and Firewall Rules inside Azure Subscription: '$($DataSubContext.Subscription.Name)' ..." -ForegroundColor Magenta
        write-host ""
        foreach ($StorageAccount in $StorageAccounts) {
            $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
            Write-Host "Verifying Storage Account: '$($StorageAccount.StorageAccountName)'... " -ForegroundColor Magenta

            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured for Storage Account: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'."
            }else {
                # No Private Endpoint
                Write-Host "Awareness! Private Endpoint is not configured on Storage Account: '$($StorageAccount.StorageAccountName)'."                 
                If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
                {
                    Write-host ""
                    Write-host "Firewall Rules detected on your Storage Account: '$($StorageAccount.StorageAccountName)'. 'Allow trusted Microsoft services to access this storage account' is not enabled!. Processing..." -ForegroundColor yellow
                    $Bypass = $StorageAccountNet.Bypass + "AzureServices"
                    Update-AzStorageAccountNetworkRuleSet $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -Bypass $Bypass
                    Write-Output "'Allow trusted Microsoft services to access this storage account' is now enabled in your Azure Storage Account '$($StorageAccount.StorageAccountName)' Network Firewall Rule" 
                           
                }else {
                    Write-Host "Public Endpoint is enabled with 'Allow trusted Microsoft services to access this storage account' in Storage Account: '$($StorageAccount.StorageAccountName)'. No action is needed." 
                }
            }
            write-host ""
        }
                   
        Write-host "`n"
        write-host "Readiness deployment completed for Storage Accounts in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }      
}


# If Azure Data Lake Gen 1 (ADLSGen1) is selected for Azure Data Source 
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "ADLSGen1")) {
    
    Write-host ""
    Write-Host "Processing Azure Data Lake Storage Gen 1..." -ForegroundColor Magenta
    Write-host ""

    foreach($Subscription in $Subscriptions) {
        # Select and process each data source subscription from the csv       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 

        Write-Host "Processing Subscription: '$($DataSubContext.Subscription.Name)'..."  -ForegroundColor Magenta   
        Write-host ""
        Write-Host "Verifying Azure Data Lake Storage Gen 1 Account' Network Rules and Permissions..." -ForegroundColor Magenta
        $AzureDataLakes = Get-AzDataLakeStoreAccount
                
        foreach ($AzureDataLake in $AzureDataLakes) {
                    
            # Verify if VNet Integration is enabled on Azure Data Lake Gen 1 Accounts in the subscription AND 'Allow all Azure services to access this Data Lake Storage Gen1 account' is not enabled
            $AzureDataLake = Get-AzDataLakeStoreAccount -name $AzureDataLake.Name 
                  
            If (($AzureDataLake.FirewallState -eq 'Enabled') -and ($AzureDataLake.FirewallAllowAzureIps -eq 'Disabled')) {
                       
                Write-host ""
                Write-host "Firewall Rules detected on your Azure Data Lake Storage: '$($AzureDataLake.Name)'. 'Allow all Azure services to access this Data Lake Storage Gen 1 account' is not enabled! Processing..." -ForegroundColor yellow
            #Set network rules                         
                set-AzDataLakeStoreAccount -AllowAzureIpState Enabled -Name $AzureDataLake.Name
                Write-Output "'Allow all Azure services to access this Data Lake Storage Gen 1 account' is now enabled in your Azure Storage Account '$($StorageAccount.StorageAccountName)' Network Firewall Rule" 
                        
            }else {
                Write-Host "'Allow all Azure services to access this Data Lake Storage Gen 1 account' is enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'. No action is needed."
            }
                
            #Set ACL
            $AzureDataLakeACLs = Get-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -ErrorAction SilentlyContinue -ErrorVariable error1
            if ($error1 -match "doesn't originate from an allowed virtual network, based on the configuration of the Azure Data Lake account") {
                    #Missing network rules from client machine to ADLS Gen 1
                    Write-host "Unable to access Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'! Update firewall rules to allow access from your IP Address!" -ForegroundColor red 
                      
            }else {
                $missingacl = $null
                foreach ($AzureDataLakeACL in $AzureDataLakeACLs) {
                    if (($AzureDataLakeACL.Permission -match 'x') -and ($AzureDataLakeACL.Permission -match 'r') -and ($AzureDataLakeACL.id -eq $PurviewAccountMSI)) {
                        Write-host "'Read' and 'Execute' permission is enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'. No action is needed."
                        $missingacl = 1  
                        break
                    }
                }
                if ($null -eq $missingacl) { 
                                        
                    Write-host ""
                    Write-host "'Read' and 'Execute' permission is not enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'! Processing..." -ForegroundColor yellow
                    Set-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -Permissions ReadExecute -AceType user -id $PurviewAccountMSI -Recurse
                    Write-Output "'Read' and 'Execute' permission is now enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
           
                }
            }
                         
            Write-host "`n"
        } 
                
        write-host "Readiness deployment completed for Azure Data Lake Storage Gen 1 Accounts in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n"                    
    }    
    
}

# If Azure Synapse (Synapse) is selected for Azure Data Source 
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "Synapse")) {

    Write-Host ""
    Write-Host "Processing Azure Synapse..." -ForegroundColor Magenta
    Write-host ""
       
    foreach($Subscription in $Subscriptions) {
        # Select and process each data source subscription from the csv       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 
        Write-Host "Processing Subscription: '$($DataSubContext.Subscription.Name)'..."  -ForegroundColor Magenta
      
        Write-Host "Processing RBAC assignments for Azure Purview Account $($PurviewAccount) for $AzureDataType ..." -ForegroundColor Magenta
        $ControlPlaneRole = "Reader"
        $RBACScope = "/subscriptions/" + $DataSubContext.Subscription.SubscriptionId

        #Check if Reader role is assigned            
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $RBACScope
                    
        if (!$ExistingReaderRole) {
            #Assign Reader role to Azure Purview 
            New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $RBACScope
            Write-Output "Azure RBAC 'Reader' role is now assigned to Azure Purview at the selected scope!"
        }else {
            Write-Output "Azure RBAC 'Reader' role is already assigned to Azure Purview at the selected scope. No action is needed." 
        }
                    
        Write-Host ""
        #Verify whether RBAC is already assigned, otherwise assign RBAC
        $Role = "Storage Blob Data Reader"
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                        
        if (!$ExistingRole) {
            New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope  
            Write-Output  "Azure RBAC 'Storage Blob Data Reader' role is now assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'."
        }else {
            Write-Output "Azure RBAC 'Storage Blob Data Reader' role is already assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'. No action is needed." 
        }

        #get az kv secrets
        $PurviewKV = Get-AzKeyVault -VaultName $Subscription.KeyVaultName
        If ($null -eq $PurviewKV) 
        {
            Write-Host "Key Vault '$($Subscription.KeyVaultName)' Account not found!" -ForegroundColor red
        }else {
            # get sql admin user 
            $AzSQLUserName = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLUserName
            If ($null -eq $AzSQLUserName) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLUserName)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLUserName =  $AzSQLUserName.SecretValue     
            }
            
            #get sql admin password 
            $AzSQLPassword = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName -Name $Subscription.SecretNameSQLPassword
            If ($null -eq $AzSQLPassword) 
            {
                Write-Host "Key Vault Secret: $($Subscription.SecretNameSQLPassword)' not found in Key Vault Account: '$($Subscription.KeyVaultName)'!" -ForegroundColor red
            }else {
                $AzSQLPassword =  $AzSQLPassword.SecretValue
            }            
        }

        $AzureSynapseWorkspaces = Get-AzSynapseWorkspace
        foreach ($AzureSynapseWorkspace in $AzureSynapseWorkspaces) {

            Write-Host "Verifying Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'... " -ForegroundColor Magenta

            #Public and Private endpoint 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSynapseWorkspace.Id -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoints: '$($PrivateEndPoints.Name)' is configured on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'."
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name), Verifying Firewall Rules...'."
            }    
            
            $missingfwrule = $null
            $AzureSynapseServerFwRules = Get-AzSynapseFirewallRule -WorkspaceName $AzureSynapseWorkspace.Name 
            foreach ($AzureSynapseServerFwRule in $AzureSynapseServerFwRules) {
                if (($AzureSynapseServerFwRule.StartIpAddress -contains "0.0.0.0" ) -or $AzureSynapseServerFwRule.EndIpAddress -contains "0.0.0.0")
                {
                    $missingfwrule = 1  
                    break

                }   
            }
            if ($null -eq $missingfwrule) 
                {
                    #Azure IPs are not allowed to access Azure Synapse Workspace     
                    Write-host ""
                    Write-host "'Allow Azure services and resources to access this server' is not enabled on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'! Processing..." -ForegroundColor yellow    
                    New-AzSynapseFirewallRule -WorkspaceName $AzureSynapseWorkspace.Name -Name "AllowAllWindowsAzureIps" -StartIpAddress "0.0.0.0" -EndIpAddress "0.0.0.0"
                    Write-Output "'Allow Azure services and resources to access this server' is now enabled on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)' "         
            }    
                   
            #Verify / Assign Azure AD Admin                   
            $AzSynapseAADAdminConfigured = Get-AzSynapseSqlActiveDirectoryAdministrator -WorkspaceName $AzureSynapseWorkspace.Name 
            
            # Validate whether the sql admin user account that is provided in csv, actually exists in AAD  
            $AzSynapseAADAdminPrompted =  $AzSynapseAADAdminPrompted = ([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)
            $AzSynapseAADAdminPrompted = Get-AzureADUser -ObjectId $AzSynapseAADAdminPrompted
            $AzSynapseAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSynapseAADAdminPrompted.ObjectId  

            If ($null -ne $AzSynapseAADAdminConfigured){

                # Azure AD Authentucation is enabled on Azure Synapse Workspace
                Write-Host "Verifying Azure AD Authentication on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)' ..." -ForegroundColor Magenta
                  
            }else {
                        
                # Azure AD Authentucation is not enabled on Azure Synapse Workspace
                Write-Host "Azure AD Authentication is not enabled on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'! Processing..." -ForegroundColor yellow
                            
                # Set Azure AD Authentication on Azure Synapse Workspace
                Set-AzSynapseSqlActiveDirectoryAdministrator -WorkspaceName $AzureSynapseWorkspace.Name -ResourceGroupName $AzureSqlServer.ResourceGroupName -DisplayName $AzSynapseAADAdminPrompted.DisplayName
                Write-Output "Azure AD Authentication is now enabled for user: '$($AzSynapseAADAdminPrompted.DisplayName)' on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'."
                $AzSynapseAADAdminConfigured = Get-AzSynapseSqlActiveDirectoryAdministrator -WorkspaceName $AzureSynapseWorkspace.Name 
      
            }    
            #Assign SQL db_datareader Role to Azure Purview MSI on each Azure Synapse Dedicated Pool 
            $AzureSynapsePools = Get-AzSynapseSqlPool -WorkspaceName $AzureSynapseWorkspace.Name
            foreach ($AzureSynapsePool in $AzureSynapsePools) {
              
                                           
                    #Validate if the provided admin user is actually configured as AAD Admin in Azure Synapse Workspace
                    If (($AzSynapseAADAdminConfigured.DisplayName -eq $AzSynapseAADAdminPrompted.DisplayName) -OR ($AzSynapseAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSynapseAADAdminConfigured.ObjectId))
                        {

                            sqlcmd -S $AzureSynapseWorkspace.ConnectivityEndpoints.sql -d $AzureSynapsePool.SqlPoolName -I -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                            Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSynapsePool.SqlPoolName)' on Azure Synapse Workspace '$($AzureSynapseWorkspace.Name)'."

                        }else {    
                            Write-Output "'$($AzSynapseAADAdminPrompted.UserPrincipalName)' is not Admin in Azure Synapse Workspace:'$($AzureSynapseWorkspace.Name)'. '$($AzSynapseAADAdminConfigured.DisplayName)' is found as SQL Server Admin on Azure AD Authentication configuration on the server."
                               
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            $AzSynapseAADAdminPrompted = Read-Host -Prompt "Enter your Azure Synapse Workspace Administrator account that is Azure AD Integrated or press Enter to skip"
                            if (!$AzSynapseAADAdminPrompted) { 
                                Write-Host "Skipping '$($AzureSynapseWorkspace.Name)'. Azure Purview will not be able to scan this Azure Synapse Workspace!" -ForegroundColor Red 
                            }else{
                                $AzSynapseAADAdminPrompted = Get-AzureADUser -ObjectId $AzSynapseAADAdminPrompted
                                sqlcmd -S $AzureSynapseWorkspace.ConnectivityEndpoints.sql -d $AzureSynapsePool.SqlPoolName -I -U $AzSynapseAADAdminPrompted.UserPrincipalName -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                                
                                Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSynapsePool.SqlPoolName)' on Azure Synapse Workspace '$($AzureSynapseWorkspace.Name)'."
                            }   
                        }
                             
            } 
                                
            write-host ""
        }  
        Write-host "`n"
        write-host "Readiness deployment completed for Azure Synapse in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }  
}
