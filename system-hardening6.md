# Syshardening 6 writeup

Created by: Prilasey#5045, Festive Goofball#9853, Quasar#0147 and Hyperion#3326

## Scenario

Help! The kingdom of Narnia has set up a new Minecraft server, but all sorts of stuff have gone wrong! They have asked you, an honorable CTF player, to secure their system for them. It's of utmost importance, because rumor has it that the White Witch is on the move!

In this image, you will be scored based on how many security misconfigurations and vulnerabilities in the image that you can mitigate. You will recieve the flag upon reaching 90 points. At that time your should screenshot your "Scoring Report," which contains information about the vulnerabilities you have fixed and your progress in the image. This is located on your Desktop as a shortcut. Send the screenshot to Eth007#0804 on Discord for the flag.

Notes:

This server is a minecraft server, so minecraft should be running. Please make sure that it runs under the minecraft user.

Please disable any ways to run minecraft commands without logging into the minecraft world.

We've recived reports about the Nether dimension not working. Please make sure this works so that our players can get those blaze rods!

We've had some massive trolling and griefing going on. As a result, we want to disable PVP temporarily. Please do that ASAP.

The system is authorized to serve /var/www/html and /srv/files on the web.

Aslan is a lion, and therefore cannot be bothered with SSH keys. Please make sure password authentication on the SSH server remains enabled.

# Forensics

## Forensic Question 1 Correct:
```
- This is a forensics question. Answer it to get points.
- Make sure to have no non-whitespace characters between "ANSWER: " and your answer.
- EXAMPLE QUESTION: What is 4200 + 42?
- EXAMPLE ANSWER: 4242
- -------------------------------------------------------- What is the hostname of this device? ANSWER: narniacraft
```
If you search up how to get the hostname on an ubuntu image, you can simply just type hostname in the terminal and you can get the answer

## Forensic Question 2 Correct:
```
- This is a forensics question. Answer it to get points.
- Make sure to have no non-whitespace characters between "ANSWER: " and your answer.
- EXAMPLE QUESTION: What is 4200 + 42?
- EXAMPLE ANSWER: 4242
- --------------------------------------------------------

A privilege escalation vulnerability was recently found in the `pkexec` binary. What is the CVE number of the vulnerability?

ANSWER: CVE-2021-4034
```
Pwnkit is a known vulnerability that exploits memory corruption in the pkexec binary inorder to gain code execution. Given the suid binary runs this as root, an unprivileged user can exploit this to gain code execution as root. This vulnerability was discovered shortly before the image’s release date, January 30 2022.

#Forensic Question 3 Correct:
```
- This is a forensics question. Answer it to get points.
- Make sure to have no non-whitespace characters between "ANSWER: " and your answer.
- EXAMPLE QUESTION: What is 4200 + 42?
- EXAMPLE ANSWER: 4242
- --------------------------------------------------------

The website running on this server requires a password to access the administrator panel. What is the password to the administrator panel?

ANSWER: m1n3cr4ft1ng\_3v3ry\_d4y
```
So, to access the administration panel you can access the website or check the html file of the website. In the readme, it explains the website is serving files in /var/www/html/, now if we just check the index.html and scroll down to the login logic

![](img/0.png)

Now if we run the function to see what it is doing in a javascript runner:

![](img/1.png)

We can get the flag!

## Forensic Question 4 Correct:
```
- This is a forensics question. Answer it to get points.
- Make sure to have no non-whitespace characters between "ANSWER: " and your answer.
- EXAMPLE QUESTION: What is 4200 + 42?
- EXAMPLE ANSWER: 4242
- --------------------------------------------------------

RCON is a protocol used to remotely run Minecraft commands. On this server, the RCON console requires a password. What is the password?

ANSWER: y0uw1lln3v3rgu4ssth1s
```
To find the RCON password, we should check the folder associated with minecraft, as googling RCON yields we should check the server config. Once in /opt/minecraft, which is the directory provided in the readme, recursively grepping for password yields rcon.password in the server config:

![](img/2.png)

## Forensic Question 5 Correct:
```
- This is a forensics question. Answer it to get points.
- Make sure to have no non-whitespace characters between "ANSWER: " and your answer.
- EXAMPLE QUESTION: What is 4200 + 42?
- EXAMPLE ANSWER: 4242
- --------------------------------------------------------

A YouTube video was watched by an user of this device. What is the YouTube ID of the video?

Example: if the video link is "https://www.youtube.com/watch?v=dQw4w9WgXcQ", the answer is "dQw4w9WgXcQ", without quotes.

ANSWER: FNBAmpm\_LbQ
```
So if a user wants to watch a youtube video, what do they need? Well a browser, and there's only one browser on this machine, firefox. If you can check the history of that browser, you are able to find the youtube video and simply grab the ID from the link.

![](img/3.png)

Now if we click on the video, we can get the full link

# Vulnerabilities:

## Services

### SSH

SSH provides secure (if configured correctly) remote access across the network. SSH Configuration File is Owned by Root (4 pts)

It is important that the SSH configuration file is not owned by any user other than root (in conjunction with setting secure permissions) in order to ensure that unauthorized users do not edit the configuration. You can simply run "chown root:root /etc/ssh/sshd\_config" to change the ownership of the file

#### SSH Root Login Disabled (4 pts)

Root, being the privileged user, should not be able to be accessed remotely from the network, given its elevated permissions. Hence setting `PermitRootLogin no` should be set in SSH.

#### SSH Does Not Permit Empty Password (4 pts)

If empty passwords are permitted, unauthorized users can logon easily. Because the README explains that password authentication should be enabled, this setting is applicable. To set this setting simply put "PermitEmptyPasswords no" in /etc/ssh/sshd\_config

![](img/4.png)

#### SSH forces protocol 2 (4 pts)

Protocol 2 is the most updated version of the SSH protocol. SSH Protocol 2 has several advantages over SSH version 1 such as more authentication methods and having sftp support. More authentication methods are useful for security. To set this setting put "Protocol 2" in /etc/ssh/sshd\_config

### Nginx

#### NGINX Server Tokens Disabled (4 pts)

Set ServerTokens off in /etc/nginx/nginx.conf. Server tokens leaks a substantial amount of information on the servers and can help attackers figure out what vulnerabilities the server may be vulnerable to based on the version.

#### NGINX Off-By-Slash Misconfiguration (4 pts)

The NGINX configuration in nginx.conf has
```
location /cdn {

  limit\_except GET HEAD POST { deny all; } alias /srv/files/;

  default\_type text/plain;

  limit\_req zone=one burst=5;

}
```

This is insecure as a malicious user could visit “cdn..” to get Local File Inclusion (LFI), which an attacker can use to read the contents of files in /srv. To patch this, we change “location /cdn” to “location /cdn/”, which patches the LFI, as the malicious user can no longer pass “cdn..”.

#### NGINX Root Properly Set (4 pts)

In the readme, it states NGINX is authorized to server /var/www/html/ and /srv/files/, /srv/files is being served, however, /var/www/html/ is not being served. Instead /etc/nginx is being served in the file

(Put screenshot will or else bald)

So to fix this we can just simply replace /etc/nginx with /var/www/html

### Minecraft

#### Minecraft RCON Disabled (3 pts)

In the readme, it states users should not be able to execute commands remotely without logging into the minecraft world, funny enough:

![](img/5.png)

So we should probably disable this. But how? Well let's look in the /opt/minecraft, because we already know that's where the directory is for minecraft, and probably will have configuration files there.

We know the minecraft service runs in this directory because, if you check the home for the minecrafts service user

![](img/6.png)

And if you check the service file in systemd:

![](img/7.png)

So let's see where we can disable rcon:

![](img/8.png)

Oh nice! If we just put "enable-rcon=false" in /opt/minecraft/server/server.properties we can disable rcon.

#### Minecraft Nether Dimension Enabled (3 pts)

The readme requests for the nether dimension to be enabled, since we already found where the configuration file is (/opt/minecraft/server/server.properties), we can just look for any mentions of nether. Sure enough:

![](img/9.png)

#### Minecraft Runs As The Minecraft User (3 pts)

The readme explains it wants the Minecraft service to run as the Minecraft user. Minecraft itself in this case is a service. From a security standpoint, this makes sense. If the Minecraft service were to be compromised and the user was being run as something privileged, attackers could leverage the service. In Ubuntu, services are handled by systemd. This vuln is related to systemd sandboxing (research it on your own!).

![](img/10.png)

To change the user that runs Minecraft, you can change the "user" parameter in it's systemd service file (/etc/systemd/system/minecraft.service) to the user minecraft.

Currently, it's being run as the user root

![](img/11.png)

So we can just change it to:

![](img/12.png)

Minecraft runs without the ability to edit system files (3 pts)

So, systemd, we know we can sandbox the services to secure the services that we run. And again, we sandbox services because if that service were to be compromised, the privileges an attacker would have would be limited. If we just read what it's in the systemd file:

![](img/13.png)

At first glance, you should already be a little bit sussed out. Protectsystem? That sounds like a secure option, why would we want to disable that? Most of the time when you are confronted with a new service the best way to deal with them is literally just to use your intuition and basic cybersecurity principles. If something sounds secure or seems secure, most of the time your right. To confirm whether or not you are right just simply read documentation or google.

Let's take this vuln for example:

Since we know this is a weird setting that he specifically declared, let's read what it does.

![](img/14.png)

So if this setting is set to "true" (boolean argument) then the service Minecraft is unable to write to the directories /usr, /boot/ and /efi. If it's set to "full" however, the the /etc/ directory should also be non-writable in addition to the previous directories mentioned. If it's set to "strict" then all files will be unwritable.

Now the minecraft service, needs access to write to /opt/minecraft (needs to be able to write to files to say who's banned and who is op in the server and etc.) so we can't just set the service to strict.

Note from Quasar: Strict would break minecraft here, as the service needs to be able to write to /opt.

Note from Prilasey: REALISTICALLY, minecraft does not need access to /etc, /usr, /boot, or /efi so I'm pretty sure the best option is actually full but eth007 scored it as true so I don't know.

We can set the ProtectSystem to "true" in /etc/systemd/system/minecraft.service so it cannot write to those directories if the service were compromised.

#### Minecraft Player-Versus-Player Combat Temporarily Disabled (3 pts)

The readme requests that in order to stop griefing on the server, you need to disable PVP. If we check the configuration file that we found earlier for the occurrences of "pvp":

![](img/15.png)

We can see it's currently enabled, so we can just set "pvp=false" in /opt/minecraft/server/server.properties

## Users

### Removed malicious user creation script (4 pts)

If you tried to modify anything with the users there was a script being run in /etc/crontab that made it basically impossible

![](img/16.png)

Contents of the script:

![](img/17.png)

So basically you cannot remove or modify any of the users, groups, password, or anything related to that unless you removed the script, and removed the immutable bits from the files /etc/passwd, /etc/group, and /etc/shadow

You can accomplish this by simply typing: chattr -i (all three files mentioned)

### Malicious user Jadis removed (2 pts)

Jadis is not an authorized user mentioned in the README, and therefore is simply another entry point into the system and is unnecessary for the situation. Furthermore, jadis has the permissions of root, because her uid and gid is declared as root. To remove the user you can simply just remove them from /etc/passwd

![](img/18.png)

### Malicious user maugrim removed (2 pts)

Maugrim is not authorized in the list of users provided by the README. Again, this is just another entry point into the system and is unnecessary in this situation. To remove the user you can simply remove them from /etc/passwd

![](img/19.png)

## Sysctl

Sysctl are parameters that modify how the kernel works. To modify sysctl settings, you can modify the files in /etc/sysctl.d/ and /etc/sysctl.conf itself. Before you paste in your own secure settings, you should check those files to see if anything was preconfigured.

![](img/20.png)For example, you can find the setting kernel.randomize\_va\_space was added and the file "10-max49iscool.conf" was added

![](img/21.png)

So without even configuring settings, you can already see things that could possibly score.

### Userspace address space layout randomization enabled (3 pts)

Address space layout randomization (ASLR) randomizes the position of processes in the memory. This can protect systems from many attacks such as buffer overflow or memory exploitations as they would first require prior knowledge of where things are located. You can enable ASLR protection in /etc/sysctl.conf with: kernel.randomize\_va\_space = 2. To apply the settings you can just run "sysctl -p"

### TCP SYN cookies enabled (4 pts)

SYN flood attacks, a type of ddos attack, is where attackers can send a lot of SYN requests, filling the system's TCP connection table. Syncookies can verify whether or not the request is legitimate. To enable TCP SYN cookies, put net.ipv4.tcp\_syncookies = 1 in /etc/sysctl.conf. To apply the settings you can just run "sysctl -p"

## Misc

### PAM does not authenticate on failed login attempts (4 pts)

If you try to login to the user or use sudo, and type in the wrong password, you will notice you can authenticate without a problem. This means that pam has been modified.

In this case, if you read through the pam files you will find that the line that normally has the pam\_deny module has been replaced with the pam\_permit module

![](img/22.png)

This essentially means that even if the first line uncommented fails in authentication, the second command will simply move on and allow the failed authentication to happen.

To fix this, change the second uncommented line to:

![](img/23.png)

### Removed pwnkit exploit file (4 pts)

Ok how you should approach this, is that you should know that eth007 has quite the interest in pwnkit being exploited especially because of Forensic Question 2. An important thing to do in hunting for malware or anything, in general, is checking against defaults. If you check against defaults, you can find in /bin the proof of concept located in /bin

![](img/24.png)

But by itself, the file is completely useless, as the code needs to be compiled into a binary for actual proper use. Knowing this, we can search for binaries that aren't there by default in installation. After checking against defaults, you will find a file called "groot," which is kinda a suspicious name. To further confirm my suspicion on this file, you can check if the binary has a manual page

![](img/25.png)

If there is no man page, then we know that eth007 must've compiled the c code into this binary! We can further confirm this by simply looking into the file

![](img/26.png)

# Notable things/moments:

![](img/27.png)

![](img/28.png)

![](img/29.png)

![](img/30.png)
