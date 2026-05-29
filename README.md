# snmpcheck

## Overview
`snmpcheck.pl` is a full-featured SNMP enumeration tool written in Perl, designed for penetration testers and security professionals. It automates the process of extracting detailed information from any SNMP-enabled device - routers, switches, servers, printers, firewalls — and presents the output in a clean, structured, human-readable format.
This is a faithful Perl port of the original `snmpcheck.rb` Ruby tool, rewritten to use Net::SNMP — which provides deterministic OID index handling that resolves walk alignment issues present in some Python SNMP libraries.

## Features
CategoryData ExtractedSystemHostname, OS description, contact, location, uptimeNetwork InfoIP forwarding, TTL, TCP/UDP datagram countersInterfacesName, MAC, type, speed, MTU, in/out octets, statusIP AddressesInterface-to-IP mapping, netmask, broadcastRouting TableDestination, next-hop, mask, metricTCP SocketsLocal/remote addr:port, connection stateUDP SocketsListening local address and portStorageDevice type, size, used, allocation unitFilesystemMount point, type, access, bootable flagDevicesHardware device index, type, status, descriptionProcessesPID, name, path, parameters, run statusSoftwareInstalled package list with versionsWindowsDomain, user accounts, services, shares, IIS statsWrite AccessTests SNMP SET capability against community string

## Requirements
```
# Debian / Ubuntu / Parrot / Kali
sudo apt install libnet-snmp-perl

# Or via CPAN (any platform)
cpan Net::SNMP

# Perl >= 5.10 required (5.38 tested)
perl --version
```

<img width="1396" height="616" alt="image" src="https://github.com/user-attachments/assets/a80d26d5-ace8-4b71-80db-20c7dcbbc2e5" />

<img width="1930" height="1186" alt="image" src="https://github.com/user-attachments/assets/01bb1cf1-4c82-4218-9440-19376ec4f633" />

<img width="1388" height="368" alt="image" src="https://github.com/user-attachments/assets/de5fffba-2fd8-400b-8607-6fb548aec920" />


### Examples
```
# Basic enumeration with known community
./snmpcheck.pl -c public 192.168.70.150

# SNMPv2c (faster, supports bulk operations)
./snmpcheck.pl -c public -v 2c 192.168.70.150

# Test write access
./snmpcheck.pl -c public -w 192.168.70.150

# Skip TCP enumeration (faster, less noisy)
./snmpcheck.pl -c public -d 192.168.70.150

# Slow/unreliable target — increase timeout and retries
./snmpcheck.pl -c public -t 10 -r 3 192.168.70.150

# Full scan with write check, SNMPv2c, no TCP
./snmpcheck.pl -c public -v 2c -w -d -t 10 192.168.70.150

# Save output to file
./snmpcheck.pl -c public 192.168.70.150 | tee results.txt

# Community string brute force (wrap in shell)
for comm in public private manager admin monitor cisco; do
    ./snmpcheck.pl -c "$comm" -t 2 -d 192.168.70.150 2>/dev/null \
      | grep -q "Hostname" && echo "[HIT] $comm"
done
```

### Disclaimer
This tool is intended for authorized penetration testing and security assessments only. Use only against systems you have explicit written permission to test. The developer assumes no liability for misuse.

### Credits
Original tool: `snmpcheck.rb` by `Matteo Cantoni`
