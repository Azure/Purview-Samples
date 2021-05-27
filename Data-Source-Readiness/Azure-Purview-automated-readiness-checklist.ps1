<#requires -version 5.1
##requires -Module Az#>

<#
.SYNOPSIS
This script is aimed to help organizations to verify required RBAC role assignments and network access for various Azure Data Sources across one or multiple subscriptions in order to be able to register and scan Azure data sources in Azure Purview. 
Run this script after you deploy your Azure Purview Account and before registering and scanning data sources. 

.DESCRIPTION
This PowerShell script is aimed to assist Azure Subscriptions administrators to identify required RBAC and network access for Azure Purview Account to scan resources under a defined list of Azure Subscriptions. 
This version is reduced in prompts during the execution. 

PRE-REQUISITES:
1. Required PowerShell Modules:
    Az 
    Az.Synpase
    AzureAD

    Note: If you already have the Az modules installed, you may still encounter the following error:
        The script cannot be run because the following modules that are specified by the "#requires" statements of the script are missing: Az.at line:0 char:0
        To resolve this issue, please run the following command to import the Az modules into your current session:
        Import-Module -Name Az -Verbose

2. An Azure Purview Account.

3. Azure resources such as Storage Accounts, ADLS Gen2 Azure SQL Databases or Azure SQL Managed Instances.

4. Required minimum permissions to run the script:
    4.1 For BlobStorage: Reader on data sources' subscription or Management Group
    4.2 For ADLSGen1 and ADLSGen2: Reader on data sources' subscription or Management Group
    4.3 For AzureSQLDB: Read Key Vault and have access to get/list Azure Key Vault secret where Azure SQL Admin credentials are stored.  
    4.4 For AzureSQLMI: Read Key Vault and have access to get/list Azure Key Vault secret where Azure SQL Admin credentials are stored.
    4.5 For Azure Synapse: Read Key Vault and have access to get/list Azure Key Vault secret where Azure Synapse Admin credentials are stored.
    4.6 Azure Reader role on data source subscription. 
    4.7 Azure AD (at least Global Reader) to read Azure AD users and Groups. 

5. SQLCMD

How to run the script:

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

    4. PurviewSub: Subscription ID where Azure Purview Account is deployed.


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

Clear any possible cached credentials for other subscriptions
Clear-AzContext

#Login to Azure AD 
Write-Host "Please sign in with your Azure AD administrator account:"
Connect-AzureAD

#Authentication to Azure 
Login-AzAccount
Write-Host "Please sign in with your Azure administrator credentials:"

#Az Context
$PurviewSubContext = Set-AzContext -Subscription $PurviewSub 
Write-Host "Subscription: '$($PurviewSubContext.Subscription.Name)' is selected where Azure Purview Account is deployed." -ForegroundColor Magenta

# Get Azure Purview Account
$PurviewAccountMSI = (Get-AzResource -Name $PurviewAccount).Identity.PrincipalId
If ($null -ne $PurviewAccountMSI) {
    Write-Host "Azure Purview Account '$($PurviewAccount)' is selected." -ForegroundColor Magenta
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
   

#If Azure SQL Database (AzureSQLDB) is selected for Azure Data Sources
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLDB")) 
{
    Write-Host ""
    Write-Host "Running readiness check for Azure SQL Servers..." -ForegroundColor Magenta
    Write-Host ""

    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext 

        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta
      
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
                
            #Readiness check for SQL Servers  
            write-host ""
            Write-Host "Running readiness check on Azure SQL server: '$($AzureSqlServer.ServerName)'..." -ForegroundColor Magenta
                                     
            #Public endpoint enabled
                  
            If ($AzureSqlServer.PublicNetworkAccess -like 'False') {
                #Public EndPoint disabled
                Write-Output "Awareness! Public Endpoint is not allowed on Azure SQL server: '$($AzureSqlServer.ServerName)',verifying Private Endpoints..."

            }else 
            {
                #Public EndPoint enable         
                Write-Output "Awareness! Public Endpoint is allowed on Azure SQL server: '$($AzureSqlServer.ServerName)'"

            }

            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSqlServer.ResourceId -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured on Azure SQL Server: '$($PrivateEndPoints.Name)' on Azure SQL server: '$($AzureSqlServer.ServerName)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure SQL Server: '$($AzureSqlServer.ServerName)'"
            }
                      
            #Verify Azure SQL Server Firewall settings

            $AzureSqlServerFw = Get-AzSqlServerFirewallRule -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName 
            if (($AzureSqlServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps" ) -or $AzureSqlServerFw.FirewallRuleName -contains "AllowAllAzureIPs")
            {
                Write-Output "Passed! 'Allow Azure services and resources to access this server' is enabled on Azure SQL Server's Firewall: '$($AzureSqlServer.ServerName)'." 
            }else {
                #Azure IPs are not allowed to access Azure SQL Server
                 
                Write-Host "Not Passed! 'Allow Azure services and resources to access this server' is not enabled on Azure SQL Server's Firewall: '$($AzureSqlServer.ServerName)'!" -ForegroundColor red
            }
                
            #Verify if AAD Admin is configured 
                    
            $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
            if (!$AzSQLAADAdminConfigured) {
                Write-Host "Not passed! Azure AD Admin is not configured for Azure SQL Server '$($AzureSqlServer.ServerName)!'" -ForegroundColor red
                Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSqlServer.ServerName)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! Azure AD Admin '$($AzSQLAADAdminConfigured.DisplayName)' is configured for Azure SQL Server '$($AzureSqlServer.ServerName)!'"
                #Get databases in an Azure SQL Server 
                $AzureSQLDBs = Get-AzSqlDatabase -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
                                             
                foreach ($AzureSQLDB in $AzureSQLDBs) {
                    if ($AzureSQLDB.DatabaseName -ne "master") {

                        Write-Host "Connecting to '$($AzureSQLDB.DatabaseName)' on Azure SQL Server: '$($AzureSqlServer.ServerName)'..." -ForegroundColor Magenta
                        $AzurePurviewMSISQLRole = sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"              

                        if (($null -ne $AzurePurviewMSISQLRole) -and ($AzurePurviewMSISQLRole -notlike "*Error*")) {
                            $AzurePurviewMSISQLRole = $AzurePurviewMSISQLRole.trim()
                            if (($AzurePurviewMSISQLRole.Contains("db_datareader")) -or ($AzurePurviewMSISQLRole.Contains("db_owner"))) {
                                Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'."
                            }else {
                                Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSQLDB.DatabaseName)' on Server:'$($AzureSqlServer.ServerName)'" -ForegroundColor red
                            } 

                        }
                                                            
                    }             
                  
                } 
            }     
              
            
        }  
        Write-Host ""
        write-host "Readiness check completed for SQL Servers in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        write-host "`n"
    } 

}

# If Azure SQL Managed Instance (AzureSQLMI) is selected for Azure Data Source
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLMI")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure SQL Managed Instances..." -ForegroundColor Magenta
    Write-Host ""    
       
    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext
    
        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta
          
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
                 
            #Readiness check for SQL Managed Instances  
            Write-Host ""
            Write-Host "Running readiness check on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'..." -ForegroundColor Magenta

            # Public / Private Endpoint    
            If ($AzureSqlMI.PublicDataEndpointEnabled -like 'False')
                {
                    Write-Host "Not Passed! Public Endpoint is disabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'. Scanning Azure SQL Managed Instances through public endpoint is not yet supported by Purview!" -ForegroundColor red

                }else{
                    Write-Host "Passed! Public Endpoint is enabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'."
                }    
                                        
                #Verify NSG Rules
                  
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

                foreach ($nsgRule in $nsgRules) {
                    if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                        if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains $AzureSQLMIPorts)) {
                            Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts."
                            $nsgRuleAllowing = 1
                        }else{
                            $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                            foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                if ($nsgRulePortRange -match "-") {
                                    $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                    if (($AzureSQLMIPorts -le $nsgRulePortRangeHigh) -and ($AzureSQLMIPorts -ge $nsgRulePortRangeLow)) {
                                        Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts."
                                        $nsgRuleAllowing = 1
                                    }
                                }
                            }
                        }		
                    }else{
                                  
                    }
                }
                  
                if ($nsgRuleAllowing -eq 0) {
                    Write-Host "Not Passed! No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts!" -ForegroundColor Red 
                }
                    
                #Checking port 1433
                    
                If ($AzureSqlMI.ProxyOverride = "Redirect") 
                {
                    foreach ($nsgRule in $nsgRules) {
                        if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                            if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains "1433")) {
                                Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433."
                                $nsgRuleAllowing = 1
                            }else{
                                $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                                foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                    if ($nsgRulePortRange -match "-") {
                                        $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                        if ((1433 -le $nsgRulePortRangeHigh) -and (1433 -ge $nsgRulePortRangeLow)) {
                                            Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through ports 1433."
                                            $nsgRuleAllowing = 1
                                        }
                                    }
                                }
                            }		
                        }else{
                                      
                        }
                    }
                      
                    if ($nsgRuleAllowing -eq 0) {
                        Write-Host "Not Passed! No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433!" -ForegroundColor Red 
                    }
                }
                    
                #Verify if AAD Admin is configured
                    
                $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                 
                if (!$AzSQLMIAADAdminConfigured) {
                    Write-Host "Not passed! Azure AD Admin is not configured for Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)!'" -ForegroundColor red
                    Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSqlMI.ManagedInstanceName)'!" -ForegroundColor red
                }else {
                    Write-Host "Passed! Azure AD Admin '$($AzSQLMIAADAdminConfigured.DisplayName)' is configured for Azure SQL Managed Instance $($AzureSqlMI.ManagedInstanceName)!'"
                       
                    #Get databases in an Azure SQL Managed Instance 
                    $AzureSQLMIDBs = Get-AzSqlInstanceDatabase -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName                     
                    foreach ($AzureSQLMIDB in $AzureSQLMIDBs) {
                        if (($AzureSQLMIDB.Name -ne "master") -or ($AzureSQLMIDB.Name -ne "model") -or ($AzureSQLMIDB.Name -ne "msdb") -or ($AzureSQLMIDB.Name -ne "tempdb")) 
                        {
                            $AzureSqlMIFQDN = $AzureSqlMI.ManagedInstanceName + ".public." + $AzureSqlMI.DnsZone +"."+ "database.windows.net,3342"
                            Write-Host "`n"
                            Write-Host "Connecting to '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSqlMIFQDN)'" -ForegroundColor Magenta
                                                            
                            $AzurePurviewMSISQLMIRole = sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"
                            
                            if (($null -ne $AzurePurviewMSISQLMIRole) -and ($AzurePurviewMSISQLMIRole -notlike "*Error*")) {
                            $AzurePurviewMSISQLMIRole = $AzurePurviewMSISQLMIRole.trim()
                            if (($AzurePurviewMSISQLMIRole.Contains("db_datareader")) -or ($AzurePurviewMSISQLMIRole.Contains("db_owner"))) {
                                Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'." 
                            }else {
                                Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSQLMIDB.Name)' on Server:'$($AzureSqlMI.ManagedInstanceName)'" -ForegroundColor red
                            } 
                        }             
                    }
                }    
            }
        }          
        write-host "Readiness check completed for Azure SQL Managed Instances in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }
}

# If Azure Storage Account (BlobStorage) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "BlobStorage"))
{
    Write-Host ""
    Write-Host "Running readiness check for Azure Storage Accounts..." -ForegroundColor Magenta
    Write-host ""
    
    $ControlPlaneRole = "Reader"
    $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole
    
    #Check if Reader role is assigned at scope
  
    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)' !" -ForegroundColor red
     }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'."
     }
    
    Write-Host ""
    $Role = "Storage Blob Data Reader"

    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext
    
        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta      
        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSubContext.Subscription.SubscriptionId
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                     
        if (!$ExistingRole) {        
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'." 
        }
        $StorageAccounts = Get-AzstorageAccount
                                             
        Write-host ""
        write-Host "Running readiness check on Azure Storage Accounts' Network Rules..." -ForegroundColor Magenta
        foreach ($StorageAccount in $StorageAccounts) {
               
            # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
            $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
            If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
            {
                Write-Host "Not Passed! 'Allow trusted Microsoft services to access this storage account' is not enabled on Storage Account: '$($StorageAccount.StorageAccountName)'!" -ForegroundColor red
                     
            }else {
                Write-Host "Passed! 'Allow trusted Microsoft services to access this storage account' is enabled on Storage Account: '$($StorageAccount.StorageAccountName)'."
            }
                 
            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured for Storage Account: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Storage Account: '$($StorageAccount.StorageAccountName)'"
            }
                write-host ""
        }
            
        write-host "Readiness check completed for Storage Accounts in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }   
}

# If Azure Data Lake Storage Gen2 (ADLSGen2) is selected for Azure Data Source 
                   
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "ADLSGen2"))
{
    Write-Host ""
    Write-Host "Running readiness check for Azure Data Lake Storage Gen 2..." -ForegroundColor Magenta
    Write-host ""
     
    #Check if Reader role is assigned at scope
    
    $ControlPlaneRole = "Reader"    
    $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole

    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'!" -ForegroundColor red
     }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'." 
     }
    
    Write-Host "" 
    $Role = "Storage Blob Data Reader" 
      
    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext
    
        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta      
                          
        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSubContext.Subscription.SubscriptionId
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                    
        if (!$ExistingRole) {
           
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'." 
        }
        
        $StorageAccounts = Get-AzStorageAccount | Where-Object {$_.EnableHierarchicalNamespace -eq 'True'}                                         
        Write-host ""
        Write-Host "Running readiness check on Azure Storage Accounts' Network Rules..." -ForegroundColor Magenta
        foreach ($StorageAccount in $StorageAccounts) {
                    
            # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
            $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
            If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
            {
                Write-Host "Not Passed! 'Allow trusted Microsoft services to access this storage account' is not enabled on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)'!" -ForegroundColor red
                        
            }else {
                Write-Host "Passed! 'Allow trusted Microsoft services to access this storage account' is enabled on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)'."
            }
                 
            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured for Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)"
            }
            write-host ""
        }
            
        write-host "Readiness check completed for Azure Data Lake Storage Gen 2 in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }
}

# If Azure Data Lake Storage Gen1 (ADLSGen1) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "ADLSGen1")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure Data Lake Storage Gen 1..." -ForegroundColor Magenta
    Write-host ""       
    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        $DataSubContext = Get-AzContext
    
        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta                                
        Write-host ""
        Write-Host "Running readiness check on Azure Data Lake Storage Gen 1 Account' Network Rules and Permissions..." -ForegroundColor Magenta
        $AzureDataLakes = Get-AzDataLakeStoreAccount
             
        foreach ($AzureDataLake in $AzureDataLakes) {
                    
            # Verify if VNet Integration is enabled on Azure Data Lake Gen 1 Accounts in the subscription AND 'Allow all Azure services to access this Data Lake Storage Gen1 account' is not enabled
            $AzureDataLake = Get-AzDataLakeStoreAccount -name $AzureDataLake.Name
                    
            If (($AzureDataLake.FirewallState -eq 'Enabled') -and ($AzureDataLake.FirewallAllowAzureIps -eq 'Disabled')) {
                Write-Host "Not Passed! 'Allow all Azure services to access this Data Lake Storage Gen 1 account' is not enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'!" -ForegroundColor red
                        
            }else {
                Write-Host "Passed! 'Allow all Azure services to access this Data Lake Storage Gen 1 account' is enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
            }
                
            #Verify ACL
            $AzureDataLakeACLs = Get-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -ErrorAction SilentlyContinue -ErrorVariable error1
            if ($error1 -match "doesn't originate from an allowed virtual network, based on the configuration of the Azure Data Lake account") {
                #Missing network rules from client machine to ADLS Gen 1
                Write-host "Not Passed! Unable to access Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'! Update firewall rules to allow access from your IP Address!" -ForegroundColor red 
                    
            }else {
                        
                $missingacl = $null
                foreach ($AzureDataLakeACL in $AzureDataLakeACLs) {
                    if (($AzureDataLakeACL.Permission -match 'x') -and ($AzureDataLakeACL.Permission -match 'r') -and ($AzureDataLakeACL.id -eq $PurviewAccountMSI)) {
                        Write-host "Passed! 'Read' and 'Execute' permission is enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
                        $missingacl = 1  
                        break
                    }
                }
                   
                if ($null -eq $missingacl) { Write-host "Not Passed! 'Read' and 'Execute' permission is not enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'!" -ForegroundColor red }
                    Write-host "`n"
            }    
        } 
                
        write-host "Readiness check completed for Azure Data Lake Storage Gen 1 Accounts in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n"                    
    }     
}

# If Azure Synapse (Synapse) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "Synapse"))
{
    Write-Host ""
    Write-Host "Running readiness check for Azure Synapse..." -ForegroundColor Magenta
    Write-host ""
    
    $ControlPlaneRole = "Reader"
    $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole
    
    #Check if Reader role is assigned at scope
  
    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)' !" -ForegroundColor red
     }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'."
     }
    
    Write-Host ""
    $Role = "Storage Blob Data Reader"

    foreach($Subscription in $Subscriptions) {
        # select data source subscriptions       
        $currentSubscription++;            
        $DataSub = Select-AzSubscription -SubscriptionId $Subscription.SubscriptionId;
        Write-Host $error3
        $DataSubContext = Get-AzContext
    
        Write-Host "Running readiness check on '$($DataSubContext.Subscription.Name)'"  -ForegroundColor Magenta 

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

        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSubContext.Subscription.SubscriptionId
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                     
        if (!$ExistingRole) {        
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to Azure Purview Account: '$PurviewAccount' at Subscription: '$($DataSubContext.Subscription.Name)'." 
        }
          
        #Get Synapse workspaces
        $AzureSynapseWorkspaces = Get-AzSynapseWorkspace
        foreach ($AzureSynapseWorkspace in $AzureSynapseWorkspaces) {
                
            #Readiness check for Synapse Workspaces  
            write-host ""
            Write-Host "Running readiness check on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'..." -ForegroundColor Magenta
                                     
            #Public endpoint enabled
                  
            If ($AzureSynapseWorkspace.PublicNetworkAccess -like 'False') {
                #Public EndPoint disabled
                Write-Output "Awareness! Public Endpoint is not allowed on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)',verifying Private Endpoints..."

            }else 
            {
                #Public EndPoint enable         
                Write-Output "Awareness! Public Endpoint is allowed on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"

            }

            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSynapseWorkspace.Id -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured on Azure Synapse Workspace: '$($PrivateEndPoints.Name)' on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"
            }
                      
            #Verify Azure Synapse Workspace Firewall settings
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
                    Write-Host "Not Passed! 'Allow Azure services and resources to access this server' is not enabled on Azure Synapse Workspace's Firewall: '$($AzureSynapseWorkspace.Name)'!" -ForegroundColor red
                }else{ 
                    Write-Output "Passed! 'Allow Azure services and resources to access this server' is enabled on Azure Synapse Workspace's Firewall: '$($AzureSynapseWorkspace.Name)'." 
            }    
            #Verify if AAD Admin is configured 
                    
            $AzSynapseAADAdminConfigured = Get-AzSynapseSqlActiveDirectoryAdministrator -WorkspaceName $AzureSynapseWorkspace.Name 
            if (!$AzSynapseAADAdminConfigured) {
                Write-Host "Not passed! Azure AD Admin is not configured for Azure Synapse Workspace '$($AzureSynapseWorkspace.Name)!'" -ForegroundColor red
                Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSynapseWorkspace.Name)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! Azure AD Admin '$($AzSynapseAADAdminConfigured.DisplayName)' is configured for Azure Synapse Workspace '$($AzureSynapseWorkspace.Name)!'"
                #Get databases in an Azure Synapse Workspace 
                $AzureSynapsePools = Get-AzSynapseSqlPool -WorkspaceName $AzureSynapseWorkspace.Name
                                             
                foreach ($AzureSynapsePool in $AzureSynapsePools) {
                    
                    Write-Host "Connecting to '$($AzureSynapsePool.SqlPoolName)' on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'..." -ForegroundColor Magenta
                  
                    $AzurePurviewMSISynapseRole = sqlcmd -S $AzureSynapseWorkspace.ConnectivityEndpoints.sql -d $AzureSynapsePool.SqlPoolName -I -U (([System.Net.NetworkCredential]::new("", $AzSQLUserName).Password)) -P (([System.Net.NetworkCredential]::new("", $AzSQLPassword).Password)) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"              
                    
                    if (($null -ne $AzurePurviewMSISynapseRole) -and ($AzurePurviewMSISynapseRole -notlike "*Error*")) {
                        $AzurePurviewMSISynapseRole = $AzurePurviewMSISynapseRole.trim()
                        if (($AzurePurviewMSISynapseRole.Contains("db_datareader")) -or ($AzurePurviewMSISynapseRole.Contains("db_owner"))) {
                            Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'."
                        }else {
                            Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSynapsePool.SqlPoolName)' on Server:'$($AzureSynapseWorkspace.Name)'" -ForegroundColor red
                        } 

                    }
                  
                } 
            }       
        }  

        write-host "Readiness check completed for Azure Synapse Workspaces in '$($DataSubContext.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }   
}
