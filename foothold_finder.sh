#!/bin/bash

# Author: Tushar
# Date Creadted: 9/3/2022
# Last Modified: 13/3/2022

# Description
# This programme scans an IP address for open ports and allows user to choose between ftp, samba client, sql client, gobuster to enumerate possible footholds

# Terminal colour variables
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Orange='\033[0;33m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
Light_Gray='\033[0;37m'
Dark_Gray='\033[1;30m'
Light_Red='\033[1;31m'
Light_Green='\033[1;32m'
Yellow='\033[1;33m'
Light_Blue='\033[1;34m'
Light_Purple='\033[1;35m'
Light_Cyan='\033[1;36m'
White='\033[1;37m'
NC='\033[0m' # No Color

# BASH trap to handle ctrl+c exit
trap 'echo -e "\n${Red}[X]${NC} Ctrl+C Detected. Exiting.\n"; exit 130' SIGINT

#Checks if user is root user, or is running with root privileges
function check_root {
	if [ $EUID != 0 ]; then
		echo -e "\n${Red}[X]${NC} Please run script as root user\n"
		exit 2	
	fi
	}

function welcome {
clear
	
# Welcome message
echo -e "${Light_Cyan}Welcome to the Foothold Finder ${NC}"
                                                                                                                                  
                                                                                                                                  
echo                                                                    
	}

function manual_target {
	# For manual entry of target
	echo -e -n "\n${Orange}[?]${NC} Enter target IP: " 
	read target
	}                                                                   

function initial_scan {
	# Runs an nmap -sCV scan on target
	echo -e "${Green}[+]${NC} Your target is ${Light_Cyan} $target ${NC}!"
	echo -e "${Orange}[!]${NC} Scanning target now... "
	nmap_scan
	}

function nmap_scan {
	gather_nmap
	open_ports
	os_detect
	sleep 1
	host_script
	}

function gather_nmap {
	#Puts result of nmap scan into an array
	readarray -t res < <(nmap -sCV $target)
	}
	
function gather_gobuster {
	#gobuster scan to enumerate directories using the small wordlist and select filetypes
	gobuster dir -x "php, xml, html, json, xml, txt, css" -u http://$target -w /usr/share/dirb/wordlists/small.txt
	}
	
function open_ports {
echo

# Declaration of arrays
declare -a ports
declare -a protocols
declare -a services
declare -a versions
declare -a entries

echo -e "\nOpen Ports on $target: \n"

#Prints out the results of the nmap scan into a orderly table with different colours for different columns. Also sorts the Ports, Protocols, Services, and Versions into different arrays

printf "\t|%10s|%10s|%10s\t|%10s\n" "Port" "Protocol" "Service" "Version"
	for element in "${res[@]}"; do
		if [[ "$element" =~ "open" && "$element" != *OSScan* ]]; then
			port=$(echo $element | cut -d"/" -f 1)
			ports+=("$port")
			protocol=$(echo $element | cut -d"/" -f 2 | awk '{print $1}')
			protocols+=("$protocol")
			service=$(echo $element | cut -d"/" -f 2 | awk '{print $3}')
			services+=("$service")
			version=$(echo $element | cut -d"/" -f 2 | awk '{for(i=4;i<=NF;++i) printf "%s ", $i; print ""}')
			versions+=("$version")
			printf "\t|${Light_Cyan}%10s${NC}|${Light_Purple}%10s${NC}|${Light_Green}%10s${NC}\t|${Light_Red}%10s${NC}\n" "${port}" "${protocol}" "${service}" "${version}"
		fi
	done
	
# If no open ports are detected this message will appear instead and exit out of programme
	if [[ "${#ports[@]}" -eq 0 ]]; then
		echo -e "\n\n${Light_Red}[X]${NC} It looks like your target has NO ports open. Better luck next time!"
		exit
	fi
	
	echo

# The following for and if statements show up if HTTPS, SMB, FTP, and/or MSSQL servers are running on the ports.	
	for element in "${ports[@]}"; do
		if [[ "$element" =~ "80" ]]; then
			entries+=("http")
			echo -e "${Orange}[!]${NC} HTTP Server Online"
		fi
	done
	
	for element in "${res[@]}"; do
		if [[ "$element" =~ "microsoft-ds" ]]; then
			entries+=("smb")
			echo -e "${Orange}[!]${NC} SMB Protocol detected"
		fi
	done
	
	for element in "${res[@]}"; do
		if [[ "$element" =~ "Anonymous FTP login allowed" ]]; then
			entries+=("ftp")
			echo -e "${Orange}[!]${NC} Anonymous FTP login allowed"
		fi
	done
	
	for element in "${res[@]}"; do
		if [[ "$element" =~ "ms-sql-s" ]]; then
			entries+=("mssql")
			echo -e "${Orange}[!]${NC} Microsoft SQL Server detected"
		fi
	done
printf "\n"
	}

# The following function extracts the detected OS from the nmap scan
function os_detect {
echo -e "\nOperating System of target detected as: "
	for element in "${res[@]}"; do
		if [[ "$element" =~ "Service Info: OS" || "$element" =~ "Service Info" ]]; then
			os=$(echo $element | cut -d";" -f 1 | awk '{print substr($0,index($0,$4))}')
			echo -e "${Green}[+] ${Light_Cyan}$os${NC}\n"
		fi
	done
}

# Detects Computer Name, Domain Name, and FQDN 
function host_script {
	
	declare -a coms
	declare -a doms
	declare -a fqdns
	
	echo -e "\nHost Details Detection: "
	for element in "${res[@]}"; do
		if [[ "$element" =~ "Computer name" ]]; then
			com_name=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			coms+=("$com_name")
			echo -e "${Green}[+]${NC} Computer Name: ${Light_Cyan}$com_name${NC} "
			
		fi
		
		if [[ "$element" =~ "Domain name" ]]; then
			dom_name=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			doms+=("$dom_name")
			echo -e "${Green}[+] ${Light_Cyan} Domain Name: ${Light_Cyan}$dom_name${NC} "
		fi
		
		if [[ "$element" =~ "FQDN" ]]; then
			fqdn=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			fqdns+=("$fqdn")
			echo -e "${Green}[+] ${Light_Cyan} FQDN: ${Light_Cyan}$fqdn${NC} "
		fi
	done
	
# If not detected, the user will also be informed
	
	if [[ "${#coms[@]}" -eq 0 ]]; then
		echo -e "${Light_Red}[X]${NC} No Computer Name detected."
	fi
	
	if [[ "${#doms[@]}" -eq 0 ]]; then
		echo -e "${Light_Red}[X]${NC} No Domain Name detected."
	fi
	
	if [[ "${#fqdns[@]}" -eq 0 ]]; then
		echo -e "${Light_Red}[X]${NC} No FQDN detected."
	fi
	
	}
	
	
# Script calls ftp into target ip
function ftp_entry {
	echo -e "\t${Green}[+]${NC} Use Username: ${Light_Cyan}anonymous${NC} "
	echo -e "\t${Green}[+]${NC} When prompted for password, just hit ${Light_Cyan}Enter${NC} "
	ftp $target
	}

# Result of displaying smb shares are put into an array to organise 
function gather_smb {
	readarray -t smbres < <(smbclient -NL //$target/)
	}
	
function smb_list {
	
declare -a sharenames
declare -a types
declare -a comments

echo -e "\nSMB List on $target: \n"

#Prints out the results of smb shares into a orderly table with different colours for different columns. Also sorts the sharename, types, and comments into different arrays
printf "\t|%10s|%10s|%10s\t|%10s\n" "Sharename" "Type" "Comment"
	for share in "${smbres[@]}"; do
		if [[ "$share" =~ "Disk" || "$share" =~ "IPC" ]]; then
			sharename=$(echo "$share" | awk '{print $1}')
			sharenames+=("$sharename")
			type=$(echo "$share" | awk '{print $2}')
			types+=("$type")
			comment=$(echo $share | awk '{for(i=3;i<=NF;++i) printf "%s ", $i; print ""}')
			comments+=("$comment")
			printf "\t|${Light_Cyan}%10s${NC}|${Light_Purple}%10s${NC}|${Light_Green}%10s${NC}\t|${Light_Red}%10s${NC}\n" "${sharename}" "${type}" "${comment}"
		fi
	done
smb_entry
	}

#Use the Linux smbclient to attempt to access the smb server
function smb_entry {
	echo -e "\n\n${Orange}[?]${NC} Do you wish to attempt entry to a shared disk?"
	echo
	PS3="Please select an option: "
	select opt in "${sharenames[@]}" Exit
		do
			case $opt in
			Exit)
				echo -e "${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using Foothold Finder! Bye bye!"
				exit
				;;
			*)
				smbshare="$opt"
				smbclient -N //$target/"$smbshare"
				break
				;;
			"")
				echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
				smb_entry
			esac
		done
	}

# Usage of Microsoft SQL server to gain entry into target machine. Must manually input username and password gained through other means.
function sql_entry {
	
	echo -e "${Green}[+] ${NC} Attempting to access SQL on $target"
	
	echo -e -n "\n${Orange}[?]${NC} Enter Username: " 
	read sqlusername
	
	
	echo -e -n "\n${Orange}[?]${NC} Enter Password: " 
	read sqlpassword
	
	echo -e "\n${Green}[+]${NC} Connecting to ${Light_Cyan}$sqlusername${NC}@${Light_Purple}$target${NC} using password ${Light_Red}$sqlpassword${NC}\n"
	
	
	impacket-mssqlclient "$sqlusername":"$sqlpassword"@"$target" -windows-auth
	}
	
function attempt_foothold {
	echo
	PS3="Please select which available foothold you wish to attempt: "
	select entry in "Anonymous FTP" "SMB" "MSSQL" Exit
	   do
			case $entry in
			"Anonymous FTP")
				ftp_entry
				break
				;;
			"SMB")
				gather_smb
				smb_list
				smb_entry
				break
				;;
			"MSSQL")
				sql_entry
				break
				;;
			Exit) 
				echo -e "${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using Foothold Finder! Bye bye!"
				exit
				;;
			*) 
				echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
				next_steps
				;;
			esac
		done	
	}

# List to choose next steps after inital scan.
function next_steps {
	echo -e "\n\n${Orange}[?]${NC} What next?"
	echo
	PS3="Please select an option: "
	select opt in "Gobuster Directory Enumeration" "Attempt Foothold" Exit
	do
		case $opt in
			"Gobuster Directory Enumeration")
				echo -e "\n${Light_Cyan}[+]${NC} You have selected $opt"
				gather_gobuster
				open_ports
				next_steps
				break
			;;
			
			"Attempt Foothold")
				echo -e "\n${Light_Cyan}[+]${NC} You have selected $opt"
				attempt_foothold
				open_ports
				next_steps
				break
			;;
			Exit) 
				echo -e "\n${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using the Foothold Finder! Bye bye!"
				exit
			;;
			*) 
				echo -e "\n${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
				next_steps
			;;
		esac
	done 
	}
	

check_root
welcome
manual_target
initial_scan
next_steps
