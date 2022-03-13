## _Foothold Finder_  

A script inspired by the processes to pwn Hack the Box's Starting Point machines.

# foothold_finder.sh
The script will scan and enumerate open ports on target machine. Highlight if SMB, MS SQL, FTP, or HTTP servers are online and user can choose to explore options based on what is highlighted.


## When script starts
Check if executed by Root user, otherwise issue reminder and quit:
![img1](./images/img1.png)

If root, proceed to welcome and target input screen:
![img2](./images/img2.png)

## Scan Phase

Run nmap -sCV scan on target
![img3](./images/img3.png)

Show open ports, services running, and versions. Also run host scripts to detect OS and Computer/Domain names.
Additionally, if FTP, SMB, SQL, or HTTP servers are running, they will be highlighted below the table.

Examples below are from HtB's Fawn, Dancing, and Archetype machines.
![img4](./images/img4.png)
![img5](./images/img5.png)
![img6](./images/img6.png)


HTTP server online. Choosing Gobuster directory enumeration. The script is set to use the small wordlist and to search for php,xml,html,json,txt,css filetypes :

![img7](./images/img7.png)
![img8](./images/img8.png)

# Foothold Finding Phase

When footholds are attempted:

## FTP Anonymous Login

FTP anonymous login being allowed is detected.
Choose option "Attempte Foothold", then choose FTP Anonymous Login. User needs to input username as anonymous and connect:
![img9](./images/img9.png)

Anonymous connection is successful. Files are accessible and can be downloaded to local machine using ```get``` command:

![img10](./images/img10.png)

## SMB

SMB server is online. Choose SMB from list - available SMB shares will be listed and user can choose if they want to connect to available shares.

![img11](./images/img11.png)

Successful connection. Files are accessible and can be downloaded to local machine using ```get``` command (similar to FTP):

![img12](./images/img12.png)

## SQL Database Entry

Using username and password found through other methods, attempt entry (via impacket mssqlclient).
Successful connection into SQL database. Username and Password obfuscated so as not to spoil the fun for people who haven't done those machines yet.

![img13](./images/img13.png)

