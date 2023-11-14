# Isa
# Name: 
Patrik Potančok xpotan00
# Date: 
14.11.2023

# Description: 
dhcp-stats is a utility designed to listen for DHCP packets on a given interface or parse them from a pcap file. It allows users to specify one or more IP prefixes to filter the packets and create statistics based on how many IP addresses are allocated to a given prefix. If it is filled by more than 50%, it logs it into the syslog. Some future updates could also work with lease time.

# Synopsis: 
./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]

# Usage examples:
## Interface 
### Input:
dhcp-stats -i eth0 192.168.1.0/24
### Output:
IP-Prefix             Max-hosts  Allocated addresses  Utilization  
192.168.1.0/24              254                    5         1.97%  

## From file
### Input:
dhcp-stats -r dhcp.pcap 192.168.1.0/24
### Output:
IP-Prefix             Max-hosts  Allocated addresses  Utilization  
192.168.1.0/24              254                    5         1.97%  
Press any key to exit...

# Files:
dhcp-stats.cpp  
input_check.cpp  
input_check.h  
prefix.cpp  
prefix.h  
README.md  
Makefile  
manual.pdf  
dgcp-stats.1  
