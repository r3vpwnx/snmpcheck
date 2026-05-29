#!/usr/bin/env perl
# =============================================================================
#  snmpcheck.pl v1.0 - SNMP Enumerator (Perl Edition)
# =============================================================================
#
#  Developer  : r3vpwnx - Dilanka Kaushal Hewage
#               Application Security Engineer | Red Teamer | CTF Player
#               https://github.com/r3vpwnx
#
#  Based on   : snmpcheck.rb v1.9 by Matteo Cantoni (www.nothink.org)
#               Original Ruby tool: https://www.nothink.org
#
#  License    : GNU General Public License v3.0
#               https://www.gnu.org/licenses/gpl-3.0.html
#
#  Purpose    : Full-featured SNMP enumeration tool for penetration testing
#               and network security assessments. Produces structured,
#               human-readable output covering system info, interfaces,
#               routing tables, TCP/UDP sockets, running processes, storage,
#               installed software, and Windows-specific MIB data.
#
# -----------------------------------------------------------------------------
#  DEPENDENCIES
#    apt install libnet-snmp-perl       (Debian/Ubuntu/Parrot/Kali)
#    cpan Net::SNMP                     (generic Perl env)
#
#  USAGE
#    chmod +x snmpcheck.pl
#    ./snmpcheck.pl [OPTIONS] <target IP>
#
#  OPTIONS
#    -p <port>        SNMP port              (default: 161)
#    -c <community>   Community string       (default: public)
#    -v <1|2c>        SNMP version           (default: 1)
#    -w               Test write access
#    -d               Disable TCP enumeration
#    -t <seconds>     Timeout                (default: 5)
#    -r <n>           Retries                (default: 1)
#    -h               Help
#
#  EXAMPLES
#    ./snmpcheck.pl -c public 10.10.10.5
#    ./snmpcheck.pl -c private -v 2c -w 10.10.10.5
#    ./snmpcheck.pl -c community -d -t 10 -r 3 10.10.10.5
# =============================================================================


use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use Net::SNMP qw(OCTET_STRING);
use Socket qw(inet_aton);

# ── constants ─────────────────────────────────────────────────────────────────

my $VERSION   = 'v1.0';
my $KW        = 30;   # key column width
my $CW        = 22;   # table cell width

# ── output helpers ────────────────────────────────────────────────────────────

sub banner {
    print "snmpcheck.pl $VERSION  -  SNMP enumerator (Net::SNMP edition)
";
    print "Perl port of snmpcheck.rb by Matteo Cantoni

";
}

sub info    { print "[+] $_[0]
" }
sub err     { print STDERR "[!] $_[0]
" }
sub section { print "
[*] $_[0]:

" }

sub kv {
    my ($k, $v) = @_;
    printf "  %-${KW}s: %s
", $k, $v // '-';
}

sub print_table {
    my ($headers, $rows) = @_;
    my $sp = '  ';
    print $sp . join('', map { sprintf "%-${CW}s", $_ } @$headers) . "
";
    print $sp . '-' x ($CW * scalar @$headers) . "
";
    for my $row (@$rows) {
        print $sp . join('', map { sprintf "%-${CW}s", $_ // '-' } @$row) . "
";
    }
}

# ── value helpers ─────────────────────────────────────────────────────────────

sub human_size {
    my ($size, $alloc) = @_;
    return 'unknown' unless defined $size && defined $alloc
                         && $size =~ /^\d+$/ && $alloc =~ /^\d+$/;
    my $b = $size * $alloc;
    return sprintf("%.2f GB", $b / 2**30) if $b >= 2**30;
    return sprintf("%.2f MB", $b / 2**20) if $b >= 2**20;
    return sprintf("%.2f KB", $b / 2**10) if $b >= 2**10;
    return "$b bytes";
}

sub fmt_mac {
    my $raw = shift // '';
    $raw =~ s/^0x//i;
    $raw =~ s/[: ]//g;
    return length($raw) == 12
        ? join(':', $raw =~ /../g)
        : $raw;
}

# ── Net::SNMP wrappers ────────────────────────────────────────────────────────
#
# Net::SNMP get_table() returns a flat hashref:
#   { '1.3.6.1.2.1.2.2.1.2.1' => 'eth0',
#     '1.3.6.1.2.1.2.2.1.2.2' => 'lo', ... }
#
# The instance suffix is simply: full_oid stripped of base_oid + '.'
# This is deterministic — no ezsnmp layout ambiguity.
# ─────────────────────────────────────────────────────────────────────────────

sub snmp_get {
    my ($sess, $oid) = @_;
    my $res = $sess->get_request(-varbindlist => [$oid]);
    return undef unless defined $res;
    my $v = $res->{$oid};
    return undef unless defined $v;
    return undef if $v =~ /^(noSuchObject|noSuchInstance|endOfMibView)$/i;
    $v =~ s/^\s+|\s+$//g;
    return $v eq '' ? undef : $v;
}

# Walk one column OID → { suffix => value }
sub walk_col {
    my ($sess, $base) = @_;
    my $res = $sess->get_table(-baseoid => $base);
    return {} unless defined $res;
    my %out;
    for my $full (sort keys %$res) {
        my $v = $res->{$full};
        next unless defined $v;
        next if $v =~ /^(noSuchObject|noSuchInstance|endOfMibView)$/i;
        $v =~ s/^\s+|\s+$//g;
        next if $v eq '';
        (my $suffix = $full) =~ s/^\Q$base\E\.//;
        $out{$suffix} = $v;
    }
    return \%out;
}

# Walk N column OIDs in parallel → [ [row values...], ... ] ordered by suffix
sub walk_cols {
    my ($sess, @oids) = @_;
    my @cols = map { walk_col($sess, $_) } @oids;
    return [] unless %{$cols[0]};

    my @rows;
    for my $suffix (sort keys %{$cols[0]}) {
        push @rows, [ map { $_->{$suffix} // '-' } @cols ];
    }
    return \@rows;
}

# ── IF type / status maps ─────────────────────────────────────────────────────

my %IF_TYPE = (
    1=>'other', 2=>'regular1822', 3=>'hdh1822', 4=>'ddn-x25', 5=>'rfc877-x25',
    6=>'ethernet-csmacd', 7=>'iso88023-csmacd', 8=>'iso88024-tokenBus',
    9=>'iso88025-tokenRing', 10=>'iso88026-man', 11=>'starLan',
    12=>'proteon-10Mbit', 13=>'proteon-80Mbit', 14=>'hyperchannel',
    15=>'fddi', 16=>'lapb', 17=>'sdlc', 18=>'ds1', 19=>'e1',
    20=>'basicISDN', 21=>'primaryISDN', 22=>'propPointToPointSerial',
    23=>'ppp', 24=>'softwareLoopback', 25=>'eon', 26=>'ethernet-3Mbit',
    27=>'nsip', 28=>'slip', 29=>'ultra', 30=>'ds3', 31=>'sip', 32=>'frame-relay',
);
my %IF_STATUS = (1=>'up', 2=>'down', 3=>'testing');

my %TCP_STATE = (
    1=>'closed', 2=>'listen', 3=>'synSent', 4=>'synReceived',
    5=>'established', 6=>'finWait1', 7=>'finWait2', 8=>'closeWait',
    9=>'lastAck', 10=>'closing', 11=>'timeWait', 12=>'deleteTCB',
);

my %STORAGE_TYPE = (
    '1.3.6.1.2.1.25.2.1.1'  => 'Other',
    '1.3.6.1.2.1.25.2.1.2'  => 'Ram',
    '1.3.6.1.2.1.25.2.1.3'  => 'Virtual Memory',
    '1.3.6.1.2.1.25.2.1.4'  => 'Fixed Disk',
    '1.3.6.1.2.1.25.2.1.5'  => 'Removable Disk',
    '1.3.6.1.2.1.25.2.1.6'  => 'Floppy Disk',
    '1.3.6.1.2.1.25.2.1.7'  => 'Compact Disc',
    '1.3.6.1.2.1.25.2.1.8'  => 'RamDisk',
    '1.3.6.1.2.1.25.2.1.9'  => 'Flash Memory',
    '1.3.6.1.2.1.25.2.1.10' => 'Network Disk',
);

my %FS_TYPE = (
    '1.3.6.1.2.1.25.3.9.1'  => 'Other',    '1.3.6.1.2.1.25.3.9.2'  => 'Unknown',
    '1.3.6.1.2.1.25.3.9.3'  => 'BerkeleyFFS', '1.3.6.1.2.1.25.3.9.4' => 'Sys5FS',
    '1.3.6.1.2.1.25.3.9.5'  => 'Fat',      '1.3.6.1.2.1.25.3.9.6'  => 'HPFS',
    '1.3.6.1.2.1.25.3.9.7'  => 'HFS',      '1.3.6.1.2.1.25.3.9.8'  => 'MFS',
    '1.3.6.1.2.1.25.3.9.9'  => 'NTFS',     '1.3.6.1.2.1.25.3.9.10' => 'VNode',
    '1.3.6.1.2.1.25.3.9.11' => 'Journaled', '1.3.6.1.2.1.25.3.9.12' => 'iso9660',
    '1.3.6.1.2.1.25.3.9.13' => 'RockRidge', '1.3.6.1.2.1.25.3.9.14' => 'NFS',
    '1.3.6.1.2.1.25.3.9.15' => 'Netware',  '1.3.6.1.2.1.25.3.9.16' => 'AFS',
    '1.3.6.1.2.1.25.3.9.17' => 'DFS',      '1.3.6.1.2.1.25.3.9.18' => 'Appleshare',
    '1.3.6.1.2.1.25.3.9.19' => 'RFS',      '1.3.6.1.2.1.25.3.9.20' => 'DGCFS',
    '1.3.6.1.2.1.25.3.9.21' => 'BFS',      '1.3.6.1.2.1.25.3.9.22' => 'FAT32',
    '1.3.6.1.2.1.25.3.9.23' => 'LinuxExt2',
);

my %DEV_TYPE = (
    '1.3.6.1.2.1.25.3.1.1'  => 'Other',    '1.3.6.1.2.1.25.3.1.2'  => 'Unknown',
    '1.3.6.1.2.1.25.3.1.3'  => 'Processor','1.3.6.1.2.1.25.3.1.4'  => 'Network',
    '1.3.6.1.2.1.25.3.1.5'  => 'Printer',  '1.3.6.1.2.1.25.3.1.6'  => 'Disk Storage',
    '1.3.6.1.2.1.25.3.1.10' => 'Video',    '1.3.6.1.2.1.25.3.1.11' => 'Audio',
    '1.3.6.1.2.1.25.3.1.12' => 'Coprocessor', '1.3.6.1.2.1.25.3.1.13' => 'Keyboard',
    '1.3.6.1.2.1.25.3.1.14' => 'Modem',    '1.3.6.1.2.1.25.3.1.15' => 'Parallel Port',
    '1.3.6.1.2.1.25.3.1.16' => 'Pointing', '1.3.6.1.2.1.25.3.1.17' => 'Serial Port',
    '1.3.6.1.2.1.25.3.1.18' => 'Tape',     '1.3.6.1.2.1.25.3.1.19' => 'Clock',
    '1.3.6.1.2.1.25.3.1.20' => 'Volatile Memory',
    '1.3.6.1.2.1.25.3.1.21' => 'Non Volatile Memory',
);

my %DEV_STATUS = (1=>'unknown',2=>'running',3=>'warning',4=>'testing',5=>'down');

# ── enumeration ───────────────────────────────────────────────────────────────

sub enum_system {
    my $sess = shift;
    my %oids = (
        'Hostname'      => '1.3.6.1.2.1.1.5.0',
        'Description'   => '1.3.6.1.2.1.1.1.0',
        'Contact'       => '1.3.6.1.2.1.1.4.0',
        'Location'      => '1.3.6.1.2.1.1.6.0',
        'Uptime snmp'   => '1.3.6.1.2.1.1.3.0',
        'Uptime system' => '1.3.6.1.2.1.25.1.1.0',
    );
    return map { $_ => (snmp_get($sess, $oids{$_}) // '-') } keys %oids;
}

sub check_write_access {
    my ($sess, $hostname) = @_;
    my $res = $sess->set_request(
        -varbindlist => ['1.3.6.1.2.1.1.5.0', OCTET_STRING, $hostname]
    );
    return defined $res;
}

sub enum_network_info {
    my $sess = shift;
    my %out;
    my $fwd = snmp_get($sess, '1.3.6.1.2.1.4.1.0');
    $out{'IP forwarding'} = ($fwd eq '1') ? 'yes' : 'no' if defined $fwd;

    my %counters = (
        'Default TTL'           => '1.3.6.1.2.1.4.2.0',
        'TCP segments received' => '1.3.6.1.2.1.6.10.0',
        'TCP segments sent'     => '1.3.6.1.2.1.6.11.0',
        'TCP segments retrans'  => '1.3.6.1.2.1.6.12.0',
        'Input datagrams'       => '1.3.6.1.2.1.4.3.0',
        'Delivered datagrams'   => '1.3.6.1.2.1.4.9.0',
        'Output datagrams'      => '1.3.6.1.2.1.4.10.0',
    );
    for my $k (keys %counters) {
        my $v = snmp_get($sess, $counters{$k});
        $out{$k} = $v if defined $v;
    }
    return %out;
}

sub enum_interfaces {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.2.1.2.2.1.1',   # ifIndex
        '1.3.6.1.2.1.2.2.1.2',   # ifDescr
        '1.3.6.1.2.1.2.2.1.6',   # ifPhysAddress
        '1.3.6.1.2.1.2.2.1.3',   # ifType
        '1.3.6.1.2.1.2.2.1.4',   # ifMtu
        '1.3.6.1.2.1.2.2.1.5',   # ifSpeed
        '1.3.6.1.2.1.2.2.1.10',  # ifInOctets
        '1.3.6.1.2.1.2.2.1.16',  # ifOutOctets
        '1.3.6.1.2.1.2.2.1.7',   # ifOperStatus
    );
    my @ifaces;
    for my $r (@$rows) {
        my ($idx,$descr,$mac,$type,$mtu,$speed,$inoc,$outoc,$status) = @$r;
        my $spd = ($speed && $speed =~ /^\d+$/)
                ? int($speed) / 1_000_000 . ' Mbps'
                : ($speed // '-');
        push @ifaces, {
            'Interface'  => sprintf('[%s] %s', $IF_STATUS{$status//''}  // 'unknown', $descr//''),
            'Id'         => $idx   // '-',
            'MAC'        => fmt_mac($mac),
            'Type'       => $IF_TYPE{$type//0} // "type-${\($type//0)}",
            'Speed'      => $spd,
            'MTU'        => $mtu   // '-',
            'In octets'  => $inoc  // '-',
            'Out octets' => $outoc // '-',
        };
    }
    return @ifaces;
}

sub enum_ip {
    my $sess = shift;
    return walk_cols($sess,
        '1.3.6.1.2.1.4.20.1.2',  # ifIndex
        '1.3.6.1.2.1.4.20.1.1',  # ipAddr
        '1.3.6.1.2.1.4.20.1.3',  # netmask
        '1.3.6.1.2.1.4.20.1.4',  # broadcast
    );
}

sub enum_routing {
    my $sess = shift;
    return walk_cols($sess,
        '1.3.6.1.2.1.4.21.1.1',  # dest
        '1.3.6.1.2.1.4.21.1.7',  # nexthop
        '1.3.6.1.2.1.4.21.1.11', # mask
        '1.3.6.1.2.1.4.21.1.3',  # metric
    );
}

sub enum_tcp {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.2.1.6.13.1.2',  # local addr
        '1.3.6.1.2.1.6.13.1.3',  # local port
        '1.3.6.1.2.1.6.13.1.4',  # remote addr
        '1.3.6.1.2.1.6.13.1.5',  # remote port
        '1.3.6.1.2.1.6.13.1.1',  # state
    );
    for my $r (@$rows) {
        $r->[4] = $TCP_STATE{$r->[4]//''}  // 'unknown';
    }
    return $rows;
}

sub enum_udp {
    my $sess = shift;
    return walk_cols($sess,
        '1.3.6.1.2.1.7.5.1.1',  # local addr
        '1.3.6.1.2.1.7.5.1.2',  # local port
    );
}

sub enum_storage {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.2.1.25.2.3.1.1',  # index
        '1.3.6.1.2.1.25.2.3.1.2',  # type OID
        '1.3.6.1.2.1.25.2.3.1.3',  # description
        '1.3.6.1.2.1.25.2.3.1.4',  # alloc unit
        '1.3.6.1.2.1.25.2.3.1.5',  # size
        '1.3.6.1.2.1.25.2.3.1.6',  # used
    );
    my @out;
    for my $r (@$rows) {
        my ($idx,$typ,$descr,$alloc,$size,$used) = @$r;
        push @out, {
            'Description'     => $descr // '-',
            'Device id'       => $idx   // '-',
            'Filesystem type' => $STORAGE_TYPE{$typ//''}  // 'unknown',
            'Allocation unit' => $alloc // '-',
            'Memory size'     => human_size($size,  $alloc),
            'Memory used'     => human_size($used,  $alloc),
        };
    }
    return @out;
}

sub enum_filesystem {
    my $sess = shift;
    my %fs;
    my $idx   = snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.1.1');
    my $mount = snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.2.1');
    my $remote= snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.3.1');
    my $type  = snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.4.1');
    my $acc   = snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.5.1');
    my $boot  = snmp_get($sess, '1.3.6.1.2.1.25.3.8.1.6.1');
    $fs{'Index'}        = $idx    if defined $idx;
    $fs{'Mount point'}  = $mount  if defined $mount;
    $fs{'Remote mount'} = defined $remote && $remote ne '' ? $remote : '-'
                          if defined $remote;
    $fs{'Type'}         = $FS_TYPE{$type//''} // undef;
    delete $fs{'Type'} unless defined $fs{'Type'};
    $fs{'Access'}       = $acc    if defined $acc;
    $fs{'Bootable'}     = $boot   if defined $boot;
    return %fs;
}

sub enum_devices {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.2.1.25.3.2.1.1',  # index
        '1.3.6.1.2.1.25.3.2.1.2',  # type OID
        '1.3.6.1.2.1.25.3.2.1.5',  # status
        '1.3.6.1.2.1.25.3.2.1.3',  # descr
    );
    for my $r (@$rows) {
        $r->[1] = $DEV_TYPE{$r->[1]//''}   // 'unknown';
        my $st = $r->[2] // ''; $r->[2] = ($st =~ /^\d+$/) ? ($DEV_STATUS{$st} // 'unknown') : 'unknown';
    }
    return $rows;
}

sub enum_processes {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.2.1.25.4.2.1.1',  # pid
        '1.3.6.1.2.1.25.4.2.1.2',  # name
        '1.3.6.1.2.1.25.4.2.1.4',  # path
        '1.3.6.1.2.1.25.4.2.1.5',  # params
        '1.3.6.1.2.1.25.4.2.1.7',  # status
    );
    for my $r (@$rows) {
        $r->[4] = {1=>'running',2=>'runnable'}->{$r->[4]//''}  // 'unknown';
    }
    return $rows;
}

sub enum_software {
    my $sess = shift;
    return walk_cols($sess,
        '1.3.6.1.2.1.25.6.3.1.1',  # index
        '1.3.6.1.2.1.25.6.3.1.2',  # name
    );
}

sub enum_win_users {
    my $sess = shift;
    return values %{ walk_col($sess, '1.3.6.1.4.1.77.1.2.25.1.1') };
}

sub enum_win_services {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.4.1.77.1.2.3.1.1',
        '1.3.6.1.4.1.77.1.2.3.1.2',
    );
    my $n = 0;
    return [ map { [$n++, $_->[0]] } @$rows ];
}

sub enum_win_shares {
    my $sess = shift;
    my $rows = walk_cols($sess,
        '1.3.6.1.4.1.77.1.2.27.1.1',
        '1.3.6.1.4.1.77.1.2.27.1.2',
        '1.3.6.1.4.1.77.1.2.27.1.3',
    );
    return map { {Name=>$_->[0], Path=>$_->[1], Comment=>$_->[2]} } @$rows;
}

sub enum_win_iis {
    my $sess = shift;
    my %iis_oids = (
        'TotalBytesSentLowWord'     => '1.3.6.1.4.1.311.1.7.3.1.2.0',
        'TotalBytesReceivedLowWord' => '1.3.6.1.4.1.311.1.7.3.1.4.0',
        'TotalFilesSent'            => '1.3.6.1.4.1.311.1.7.3.1.5.0',
        'CurrentAnonymousUsers'     => '1.3.6.1.4.1.311.1.7.3.1.6.0',
        'CurrentNonAnonymousUsers'  => '1.3.6.1.4.1.311.1.7.3.1.7.0',
        'TotalAnonymousUsers'       => '1.3.6.1.4.1.311.1.7.3.1.8.0',
        'TotalNonAnonymousUsers'    => '1.3.6.1.4.1.311.1.7.3.1.9.0',
        'MaxAnonymousUsers'         => '1.3.6.1.4.1.311.1.7.3.1.10.0',
        'MaxNonAnonymousUsers'      => '1.3.6.1.4.1.311.1.7.3.1.11.0',
        'CurrentConnections'        => '1.3.6.1.4.1.311.1.7.3.1.12.0',
        'MaxConnections'            => '1.3.6.1.4.1.311.1.7.3.1.13.0',
        'ConnectionAttempts'        => '1.3.6.1.4.1.311.1.7.3.1.14.0',
        'LogonAttempts'             => '1.3.6.1.4.1.311.1.7.3.1.15.0',
        'Gets'                      => '1.3.6.1.4.1.311.1.7.3.1.16.0',
        'Posts'                     => '1.3.6.1.4.1.311.1.7.3.1.17.0',
        'Heads'                     => '1.3.6.1.4.1.311.1.7.3.1.18.0',
        'Others'                    => '1.3.6.1.4.1.311.1.7.3.1.19.0',
        'CGIRequests'               => '1.3.6.1.4.1.311.1.7.3.1.20.0',
        'BGIRequests'               => '1.3.6.1.4.1.311.1.7.3.1.21.0',
        'NotFoundErrors'            => '1.3.6.1.4.1.311.1.7.3.1.22.0',
    );
    my %out;
    for my $k (keys %iis_oids) {
        my $v = snmp_get($sess, $iis_oids{$k});
        $out{$k} = $v if defined $v;
    }
    return %out;
}

# ── main ──────────────────────────────────────────────────────────────────────

my ($opt_port, $opt_community, $opt_version, $opt_write,
    $opt_notcp, $opt_timeout, $opt_retries, $opt_help) =
   (161,       'public',       '1',          0,
    0,          5,              1,            0);

GetOptions(
    'p|port=i'      => \$opt_port,
    'c|community=s' => \$opt_community,
    'v|version=s'   => \$opt_version,
    'w|write'       => \$opt_write,
    'd|disable-tcp' => \$opt_notcp,
    't|timeout=i'   => \$opt_timeout,
    'r|retries=i'   => \$opt_retries,
    'h|help'        => \$opt_help,
) or do { err("Invalid option"); exit 1 };

if ($opt_help || !@ARGV) {
    banner();
    print <<'USAGE';
Usage: perl snmpcheck.pl [OPTIONS] <target IP>
  -p <port>       SNMP port         (default: 161)
  -c <community>  Community string  (default: public)
  -v <1|2c>       SNMP version      (default: 1)
  -w              Check write access
  -d              Disable TCP enumeration
  -t <sec>        Timeout           (default: 5)
  -r <n>          Retries           (default: 1)
  -h              Help
USAGE
    exit 0;
}

my $target = shift @ARGV;

# validate IP
unless (defined inet_aton($target)) {
    err("Invalid IP address: $target");
    exit 1;
}

if ($opt_port < 0 || $opt_port > 65535) {
    err("Invalid port: $opt_port"); exit 1;
}
if (length($opt_community) >= 25) {
    err("Community string too long (max 24 chars)"); exit 1;
}
if ($opt_retries < 0 || $opt_retries > 10) {
    err("Invalid retries value (0-10)"); exit 1;
}
unless ($opt_version =~ /^(1|2c)$/) {
    err("Invalid SNMP version. Use 1 or 2c"); exit 1;
}

banner();
info("Connecting to $target:$opt_port  SNMPv$opt_version  community='$opt_community'");
info("Write-access check enabled")  if $opt_write;
info("TCP enumeration disabled")    if $opt_notcp;
print "
";

# build session
my ($sess, $serr) = Net::SNMP->session(
    -hostname  => $target,
    -port      => $opt_port,
    -community => $opt_community,
    -version   => $opt_version,
    -timeout   => $opt_timeout,
    -retries   => $opt_retries,
    -translate => [-timeticks => 0],  # keep raw timeticks as string
);
unless (defined $sess) {
    err("Session error: $serr");
    exit 1;
}

# ── System ────────────────────────────────────────────────────────────────────
my %sys = enum_system($sess);
my @SYS_ORDER = ('Hostname','Description','Contact','Location','Uptime snmp','Uptime system');

print "[*] System information:

";
kv($_, $sys{$_}) for @SYS_ORDER;

my $is_win = ($sys{Description}//'') =~ /Windows/i;

# ── Write check ───────────────────────────────────────────────────────────────
if ($opt_write) {
    section("Write access check");
    my $hostname = $sys{Hostname} // 'snmpcheck';
    if (check_write_access($sess, $hostname)) {
        print "  [!] Write access PERMITTED
";
    } else {
        print "  Write access not permitted
";
    }
}

# ── Windows: domain + users ───────────────────────────────────────────────────
if ($is_win) {
    my $domain = snmp_get($sess, '1.3.6.1.4.1.77.1.4.1.0');
    if (defined $domain) {
        section("Domain");
        kv("Domain", $domain);
    }
    my @users = enum_win_users($sess);
    if (@users) {
        section("User accounts");
        print "  $_
" for sort @users;
    }
}

# ── Network info ──────────────────────────────────────────────────────────────
my %net = enum_network_info($sess);
if (%net) {
    section("Network information");
    kv($_, $net{$_}) for sort keys %net;
}

# ── Interfaces ────────────────────────────────────────────────────────────────
my @ifaces = enum_interfaces($sess);
if (@ifaces) {
    section("Network interfaces");
    for my $iface (@ifaces) {
        for my $k (qw(Interface Id MAC Type Speed MTU), 'In octets', 'Out octets') {
            kv($k, $iface->{$k});
        }
        print "
";
    }
}

# ── IP addresses ──────────────────────────────────────────────────────────────
my $ip_rows = enum_ip($sess);
if (@$ip_rows) {
    section("Network IP");
    print_table(['Id','IP Address','Netmask','Broadcast'], $ip_rows);
}

# ── Routing ───────────────────────────────────────────────────────────────────
my $routes = enum_routing($sess);
if (@$routes) {
    section("Routing information");
    print_table(['Destination','Next hop','Mask','Metric'], $routes);
}

# ── TCP ───────────────────────────────────────────────────────────────────────
unless ($opt_notcp) {
    my $tcp = enum_tcp($sess);
    if (@$tcp) {
        section("TCP connections and listening ports");
        print_table(['Local addr','Local port','Remote addr','Remote port','State'], $tcp);
    }
}

# ── UDP ───────────────────────────────────────────────────────────────────────
my $udp = enum_udp($sess);
if (@$udp) {
    section("Listening UDP ports");
    print_table(['Local address','Local port'], $udp);
}

# ── Windows: services / shares / IIS ─────────────────────────────────────────
if ($is_win) {
    my $svcs = enum_win_services($sess);
    if (@$svcs) {
        section("Network services");
        print_table(['Index','Name'], $svcs);
    }
    my @shares = enum_win_shares($sess);
    if (@shares) {
        section("Shares");
        for my $s (@shares) {
            kv($_, $s->{$_}) for qw(Name Path Comment);
            print "
";
        }
    }
    my %iis = enum_win_iis($sess);
    if (%iis) {
        section("IIS server information");
        kv($_, $iis{$_}) for sort keys %iis;
    }
}

# ── Storage ───────────────────────────────────────────────────────────────────
my @storage = enum_storage($sess);
if (@storage) {
    section("Storage information");
    for my $s (@storage) {
        for my $k ('Description','Device id','Filesystem type','Allocation unit',
                   'Memory size','Memory used') {
            kv($k, $s->{$k});
        }
        print "
";
    }
}

# ── Filesystem ────────────────────────────────────────────────────────────────
my %fs = enum_filesystem($sess);
if (%fs) {
    section("File system information");
    kv($_, $fs{$_}) for sort keys %fs;
}

# ── Devices ───────────────────────────────────────────────────────────────────
my $devs = enum_devices($sess);
if (@$devs) {
    section("Device information");
    print_table(['Id','Type','Status','Descr'], $devs);
}

# ── Processes ─────────────────────────────────────────────────────────────────
my $procs = enum_processes($sess);
if (@$procs) {
    section("Processes");
    print_table(['PID','Status','Name','Path','Params'], $procs);
}

# ── Software ──────────────────────────────────────────────────────────────────
my $sw = enum_software($sess);
if (@$sw) {
    section("Software components");
    print_table(['Index','Name'], $sw);
}

$sess->close();
print "
";
