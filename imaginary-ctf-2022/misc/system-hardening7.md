# Team Cyberhawks Imaginary CTF 2022: System Hardening 7
By: Shuban Pal, Will Cheng, Srijan Atti
(Hyperion#8284, Prilasey#5045, Dudeamabobby#9580)
### The Challenge
   rooReaper wasn't lying when he said that he would be back. Seems that he's infiltrated the roos' new workstation! Can you investigate and secure the system?
   The challenge is best played using VMware workstation player. However, you may be able to get it to work with other software. You will receive the flag when you reach       100 points.
### Background
   To solve this challenge, you will need to download VMware workstation 16 player. After this, you will have to upload the .vmx file  given by extracting the zipped System Hardening 7 folder provided by the challenge. This problem requires a multistep solution in which you are required to patch vulnerabilities and answer questions to reach 100. You will boot into an Ubuntu 22.04 virtual machine with a README file, Scoring Report file, and Forensic Question files on your desktop. Each vulnerability patched gives a certain amount of points based on difficulty and each Forensic Question gives you 10 points. The first action would be to read the README to see how the workstation needs to be set up. and any preferences that need to be satisfied. This challenge should be familiar if you have competed in the Air and Space Force Association's CyberPatriot competition. 

### Setup of the Desktop and Important Files
   The desktop contains 5 text files for the Forensic Questions, which each contain a question and a spot for the answer. Each Forensic Question correctly answered gives you 10 points. Then, there is a link to the README, a crucial file to work done on the system and a ScoringReport which helps you see how many points you have so far.
 ![DesktopUbuntu](https://cdn.discordapp.com/attachments/998111098559549540/998710864641269932/Desktop.png)
 
## The Good Stuff 

Here are all the vulnerabilities you had to fix in order to get 100 for the flag

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

![pingpong](https://cdn.discordapp.com/attachments/998111098559549540/998718726566330408/unknown.png)

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
![hiddenmomuser](https://cdn.discordapp.com/attachments/998111098559549540/998721085359005806/unknown.png)

### Forensic Question 4 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------

As another method of persistence, a system authentication mechanism has been sabotaged. What is the full file path to the file affected?

EXAMPLE: /bin/passwd

ANSWER: /lib/x86_64-linux-gnu/security/pam_deny.so

```

### Forensic Question 5 (10pts)
```
This is a forensics question. Answer it below.

------------------------------------------------

Some user on this machine was reading a random stackoverflow article on how to install minecraft for free, and ended up messing up the permissions on a core system directory. Which directory was this?

EXAMPLE: /etc/sudoers.d

ANSWER: /usr/lib

```

### All users removed from shadow group (4pts)

### Administrator group members correct (4pts)

### Address space layout randomization enabled (4pts)
 
### Symlink protection enabled (4pts)

### TCP SYN cookies enabled (4 pts)

### Kernel pointers hidden from unprivileged users  (4 pts)

### Kernel SYSRQ key disabled (4pts)

### Disabled SSH root login (4pts)

### Disabled SSH X11 Forwarding (4pts)

### Disabled SSH password login (4pts)

### Enabled SSH public key authentication (5pts)

### Set up SSH key for user rooYay (5pts)
