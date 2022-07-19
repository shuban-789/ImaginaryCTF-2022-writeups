# Team Cyberhawks Imaginary CTF 2022: System Hardening 7
By: Shuban Pal, Will Cheng, Srijan Atti
(Hyperion#8284, Prilasey#5045, Dudeamabobby#9580)

![meme](https://i.imgflip.com/6n6odr.jpg)

### The Challenge
   rooReaper wasn't lying when he said that he would be back. Seems that he's infiltrated the roos' new workstation! Can you investigate and secure the system?
   The challenge is best played using VMware workstation player. However, you may be able to get it to work with other software. You will receive the flag when you reach       100 points.
### Background
   To solve this challenge, you will need to download VMware workstation 16 player. After this, you will have to open the .vmx file given by extracting the zipped System Hardening 7 folder provided by the challenge. This problem requires a multistep solution in which you are required to patch vulnerabilities and answer questions to reach 100. You will boot into an Ubuntu 22.04 virtual machine with a README file, Scoring Report file, and Forensic Question files on your desktop. Each vulnerability patched gives a certain amount of points based on difficulty and each Forensic Question gives you 10 points. The first action would be to read the README to see how the workstation needs to be set up and any preferences that need to be satisfied. This challenge should be familiar if you have competed in the Air and Space Force Association's CyberPatriot competition. 

### Setup of the Desktop and Important Files
   The desktop contains 5 text files for the Forensic Questions, which each contain a question and a spot for the answer. Each Forensic Question correctly answered gives you 10 points. Then, there is a link to the README, a crucial file to work done on the system and a ScoringReport which helps you see how many points you have so far.
 ![DesktopUbuntu](https://cdn.discordapp.com/attachments/998111098559549540/998710864641269932/Desktop.png)
 
## The Good Stuff 

Here are all the vulnerabilities you had to fix in order to get 100

### Forensic Question 1 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------
 
We suspect that our server has been compromised through a download from an external site. What is the IP address of the site that we have been compromised through?
 
EXAMPLE: 13.33.33.37
 
ANSWER: 192.9.137.137

```
In order to access a website, you need a browser. The browser that is being used by default is firefox. We can assume that the external site could've been accessed by firefox. To determine that website we can check the history of the websites that were accessed:
![ExposedHistory](https://www.imgonline.com.ua/result_img/imgonline-com-ua-twotoone-nXmHBWgMW7rG83.jpg)

If you check in rooyay's downloads folder, you can find the file innocent2.xlsm. This has to be the file, because everything else in the downloads folder could not have come from any of these websites. When we click on innocent2.xlsm it redirects us to http://eth007.me/innocent2.xlsm. To figure the ip address of the website, we can just ping it:

![pingpong](https://cdn.discordapp.com/attachments/998111098559549540/998724363899641938/unknown.png)

So the answer is 192.9.137.137.

### Forensic Question 2 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------
 
The malicious file has created a backdoor for persistence. What is the full file path of the backdoor that has been created?
 
EXAMPLE: /home/rooyay/Desktop/backdoor.py
 
ANSWER: /lib/libsocket.so

```
If you enable the firewall using the “sudo ufw enable” command, it will give a warning that /lib is word writable. This is not default. So when first approaching this question, the /lib directory would be a good place to look. If you look at the /lib directory there is a file called libsocket.so, a file which has a name that should already spark a red flag on some backdoor activity due to the “socket” in its name.
![liblab](https://cdn.discordapp.com/attachments/998111098559549540/998706414170157166/unknown.png)

### Forensic Question 3 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------

A malicious hidden user has been created after the initial attack. What is the username of this user?

EXAMPLE: rooamogus

ANSWER: roomom

```
To find a hidden user, or any user really, the best approach is to view the /etc/passwd file. You can use the cat command to do so and type “sudo cat /etc/passwd” into the terminal. If you view the users, you will come by an unauthorized user named roomom, except the catch is its UID is below 1000. On machines, all human users have a UID above 1000. Which is what makes roomom a hidden user.
![hiddenmomuser](https://cdn.discordapp.com/attachments/998111098559549540/998721818124886116/unknown.png)

### Forensic Question 4 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------

As another method of persistence, a system authentication mechanism has been sabotaged. What is the full file path to the file affected?

EXAMPLE: /bin/passwd

ANSWER: /lib/x86_64-linux-gnu/security/pam_deny.so

```
If you've ever participated in any Red team VS Blue team, you'll know attackers love messing up authentication. One of the tricks they can do is replace the contents of the module pam_permit and pam_deny. In a pam stack, pam_permit says "yes" to everything. It pretty much always succeeds. pam_deny says "no to everything" and it always returns failure. However, if you replace the contents of the module, everything will succeed meaning you can authenticate by putting in any password. We can check if this is happening by looking at the hashes of the file. 
![shasumsussy](https://cdn.discordapp.com/attachments/998111098559549540/998706818266169444/unknown.png)

The hashes are the same! pam_deny.so has been replaced with the contents of pam_permit.so.

### Forensic Question 5 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------

Some user on this machine was reading a random stackoverflow article on how to install minecraft for free, and ended up messing up the permissions on a core system directory. Which directory was this?

EXAMPLE: /etc/sudoers.d

ANSWER: /usr/lib

```
If you try enabling the firewall, an interesting warning pops up warning that the /lib directory is world writable. This is not default at all and means that the permissions for the lib directory are messed up. /lib is a core system directory and thus it is the answer to this question.
![libwarn](https://cdn.discordapp.com/attachments/998111098559549540/998723945094205440/unknown.png)

### All users removed from shadow group (4pts)
It is a good practice to check the /etc/group file to see if the right users are in the right group. Groups have permissions and it can be problematic if the wrong user is in the wrong group as the wrong user has access to permissions. The user roopog was in the shadow group. Now, in the README it did not state that it was okay for roopog to be in the shadow group, and thus, we need to remove him. To do this open the /etc/group file using a text editor (this writeup will use gedit). We can type the command “sudo gedit /etc/group” to open the file, and simply delete the user roopog’s name from the shadow group.
![shadofpog](https://cdn.discordapp.com/attachments/998111098559549540/998721085359005806/unknown.png)

### Administrator group members correct (4pts)
The README specifies that only rooYay should be an administrator. Administrator privileges can be controlled using groups as well as anyone in the “sudo” group basically has access to the sudo command which lets it execute commands as root. We do not want everyone to have access to the sudo command. That is why we need to check /etc/group to make sure only authorized admins have access to that command. We can use the command “sudo gedit /etc/group” to open the group file. The sudo group has basically every single user on the system when we do this, which is not something good as we should only be giving sudo access to those users who are stated as administrators in the README. To fix this, we can simply remove the username of everyone who is not authorized to use the sudo command.

Before:
![baddy](https://cdn.discordapp.com/attachments/998111098559549540/998727062066057257/unknown.png)

After:
![goody](https://cdn.discordapp.com/attachments/998111098559549540/998727475213381683/unknown.png)

### Address space layout randomization enabled (4pts)
Address space layout randomization (ASLR) randomizes the position of processes in the memory. This can protect systems from many attacks such as buffer overflow or memory exploitations as they would first require prior knowledge of where things are located. You can enable ASLR protection in /etc/sysctl.conf with: **kernel.randomize_va_space = 2**

### Symlink protection enabled (4pts)
Symlinks have been known for having huge security issues. For example, attackers can leverage processes that write to temporary files and create a symlink to a more sensitive file. Protected_symlinks only allow symlinks to be followed if certain security conditions are met. You can enable symlink protection in /etc/sysctl.conf with: **fs.protected_symlinks = 1**

### TCP SYN cookies enabled (4 pts)

### Kernel pointers hidden from unprivileged users  (4 pts)
Kernel pointers point at a specific location in the kernel's memory. Attackers can get a lot of information which can be used in several exploits. We want to hide these pointers regardless the privilege which we may do with **kernel.kptr_restrict = 2** in /etc/sysctl.conf

### Kernel SYSRQ key disabled (4pts)
Sysrq allows you to do a lot of functions such as resetting the machine by simply hitting buttons without logging in. To disable SYSRQ, we can do **kernel.sysrq = 0** in /etc/sysctl.conf

### Disabled SSH root login (4pts)
Enabling root login for SSH can be pretty insecure as it can allow attackers to gain superuser privileges if they plan to breach your workstation via SSH. So it is always a good idea to set this parameter to "no". To apply this rule we can open the /etc/ssh/sshd_config file using "sudo gedit /etc/ssh/sshd_config", and then set the "PermitRooLogin" parameter to "no".
![sshroot](https://cdn.discordapp.com/attachments/998111098559549540/998732132321083503/unknown.png)

### Disabled SSH X11 Forwarding (4pts)
X11 sessions weren’t created with security in mind. Servers can send X11 commands to the client, if the SSH server were to be compromised they could potentially hijack the X11 session with the client. To turn this off put X11Forward no in /etc/ssh/sshd_config.
![x11](https://cdn.discordapp.com/attachments/998111098559549540/998738156855763024/unknown.png)

### Disabled SSH password login (4pts)
Since the README stated that public key authentication should be used EXCLUSIVELY. In other words, we need to get rid of all other methods of authentication which in this case is password authentication. To apply this, you put "PasswordAuthentication no" in /etc/ssh/sshd_config.
![sshpass](https://cdn.discordapp.com/attachments/998111098559549540/998731861775892490/unknown.png)

### Enabled SSH public key authentication (5pts)
The README specifically stated to enable public key authentication in ssh. To apply this, you put "PubkeyAuthentication yes" in /etc/ssh/sshd_config.
![pubkey](https://cdn.discordapp.com/attachments/998111098559549540/998732672442581094/unknown.png)

### Set up SSH key for user rooYay (5pts)
The README states to use the ssh key provided in /root as the ssh key for rooyay. To do this we can simply copy and paste /root/id_rsa.pub in /home/rooyay/.ssh/authorized_keys.
![key](https://cdn.discordapp.com/attachments/998111098559549540/998733530769133598/unknown.png)

### The Flag
Once you complete all these tasks, and your ScoringReport says you have earned 100 points, the flag will be displayed on the ScoringReport.
![flag](https://cdn.discordapp.com/attachments/998111098559549540/998736959772041236/unknown.png)

Flag: ictf{5a6a9093a22d86502368e7c1d31de30851f8c5cd06419728e8ade8c67715de8f}
### Memorable Momeents
![shesh](https://cdn.discordapp.com/attachments/997732406490570793/998754131940474931/unknown.png)

sheeeeeeeeeeeeeeeeeeesh (first first blood moment. I had to google what a first blood was tho :skull:)
