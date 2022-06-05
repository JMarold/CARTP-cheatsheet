# CARTP-cheatsheet

Azure AD cheatsheet for the CARTP course

## Index

* [General](#General)
* [Recon \ OSINT](recon.md)
* [Initial access attacks](initial-access-attacks.md)
* [Authenticated enumeration](Authenticated-enumeration.md )
* [Privilege Escalation](privilege-escalation.md)
* [Cloud <-> On-Prem - Lateral Movement](Cloud-OnPrem-lateral-movement.md)
* [Persistence](persistence.md)

## General

* List of Microsoft portals <https://msportals.io/>

* Great resources
  * <https://pentestbook.six2dez.com/enumeration/cloud/azure>
  * <https://github.com/Kyuu-Ji/Awesome-Azure-Pentest>
  * <https://github.com/dafthack/CloudPentestCheatsheets/blob/master/cheatsheets/Azure.md>

### Access C disk of a computer (check local admin)

```powershell
ls \\<COMPUTERNAME>\c$
```

### Use this parameter to not print errors powershell

```powershell
-ErrorAction SilentlyContinue
```

### Rename powershell windows

```powershell
$host.ui.RawUI.WindowTitle = "<NAME>"
```

### Save Credentials

```powershell
$creds = get-credential

$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USERNAME>', $password)
```

#### Find a specific file

```powershell
Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue
```

## PSSession

### Save pssession in variable

```powershell
$sess = New-PSSession -Credential $creds -ComputerName <IP>
```

### Run commands on machine

```powershell
Invoke-Commannd -ScriptBlock {COMMAND} -Session $sess
```

### Load script on machine

```powershell
Invoke-Commannd -Filepath <PATH TO SCRIPT> -Session $sess
```

### Copy item through PSSession

```powershell
Copy-Item -ToSession $sess -Path <PATH> -Destination <DEST> -verbose
```
