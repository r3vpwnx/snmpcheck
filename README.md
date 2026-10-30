# snmpcheck (Perl)

An SNMP enumeration tool written in Perl using `Net::SNMP`. It queries an
SNMP-enabled device and extracts system, network, storage, process and software
information in a readable report, and can test for SNMP write access.

This is a Perl port of **snmpcheck.rb by Matteo Cantoni**
(http://www.nothink.org/). All credit for the original tool and its OID coverage
belongs to the upstream author; this port reimplements that functionality on the
`Net::SNMP` backend.

## What this port adds

- `Net::SNMP`-based implementation (no external `snmpget`/`snmpwalk` binaries required)
- Deterministic handling of table/OID indexes
- An explicit SNMP write-access test (`-w`)
- Tunable timeout and retries

## Features

| Category | Data extracted |
|----------|----------------|
| System | Hostname, description, uptime, contact, location |
| Interfaces | Interface list, status, addresses |
| Routing | Routing table entries |
| Network sockets | Listening TCP and UDP ports |
| Storage | Mounted storage and disk usage |
| Processes | Running processes |
| Software | Installed software |
| Windows | Windows-specific data where exposed via SNMP |

## Requirements

- Perl 5
- `Net::SNMP` (`cpan install Net::SNMP`, or `apt install libnet-snmp-perl`)

## Install

```
git clone https://github.com/r3vpwnx/snmpcheck.git
cd snmpcheck
chmod +x snmpcheck.pl
```

## Usage

```
perl snmpcheck.pl [OPTIONS] <target IP>
```

| Option | Description | Default |
|--------|-------------|---------|
| `-p`, `--port` | SNMP UDP port | 161 |
| `-c`, `--community` | Community string | public |
| `-v`, `--version` | SNMP version (`1` or `2c`) | 1 |
| `-w`, `--write` | Test for SNMP write access | off |
| `-d`, `--disable-tcp` | Skip TCP enumeration | off |
| `-t`, `--timeout` | Request timeout (seconds) | - |
| `-r`, `--retries` | Retry count (0-10) | - |
| `-h`, `--help` | Show help | - |

Example:

```
./snmpcheck.pl -c public -d -t 10 -r 3 192.168.70.150
```

## References

- Original tool: snmpcheck.rb by Matteo Cantoni - http://www.nothink.org/

## Disclaimer

For authorized security testing and education only. Query only devices you own or
have explicit written permission to assess.

## Author (Perl port)

Dilanka Kaushal Hewage (r3vpwnx)
- Site: https://r3vpwnx.space
- Contact: dilankakaushalhewage@gmail.com

## License

GPL-3.0 - see [LICENSE](LICENSE).
