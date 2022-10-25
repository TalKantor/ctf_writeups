# Enumeration
![nmap_scan](images/bank/nmap_scan.png) </br>
## Initial Shell
When I navigated to the webserver, I saw this: </br>
![main_page](images/bank/main_page.png) </br>
Since the name of the box is bank, I added it to the ```/etc/hosts``` file, and when I searched for http://bank.htb , this is what I got: </br>
![main_page_2](images/bank/main_page_2.png) </br>
Next, I ran a fuzzing scan with gobuster: </br>
```bash
gobuster dir -u http://bank.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 30
``` 

![gobuster_results](images/bank/gobuster_results.png) </br>
When I checked ```/balance-transfer``` directory, I saw a list of files: </br>
![balance_transfer_directory](images/bank/balance_transfer_directory.png) </br>
But when I tried to access any of them, they contained encrypted usernames and passwords. </br>
I have figured that not all of the files there have the same size, I found a file with a different size and opened it: </br>
![clear_text_file](images/bank/clear_text_file.png) </br>
This file contains clear text credentials, I tried it out on the login portal: </br>
![login_portal_bypass](images/bank/login_portal_bypass.png) </br>
I navigated to the support page, and I have found an upload function there: </br>
![upload_function](images/bank/upload_function.png) </br>
I tried to upload a php reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) But I got this error: </br>
![upload_error](images/bank/upload_error.png) </br>
I inspected the source code, and found an important DEBUG comment: </br>
![debug_comment](images/bank/debug_comment.png) </br>
I renamed the php reverse shell extension to ```.htb``` , and it worked: </br>
![upload_success](images/bank/upload_success.png) </br>
I set up a netcat listener and catched the reverse shell: </br>
![initial_shell](images/bank/initial_shell.png) </br> 
# Privilege Escalation


