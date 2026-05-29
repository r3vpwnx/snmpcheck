# snmpcheck

## Overview
snmpcheck.pl is a full-featured SNMP enumeration tool written in Perl, designed for penetration testers and security professionals. It automates the process of extracting detailed information from any SNMP-enabled device — routers, switches, servers, printers, firewalls — and presents the output in a clean, structured, human-readable format.
This is a faithful Perl port of the original snmpcheck.rb Ruby tool, rewritten to use Net::SNMP — which provides deterministic OID index handling that resolves walk alignment issues present in some Python SNMP libraries.

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


### Disclaimer
This tool is intended for authorized penetration testing and security assessments only. Use only against systems you have explicit written permission to test. The developer assumes no liability for misuse.

### Credits
Original tool: snmpcheck.rb by Matteo Cantoni
