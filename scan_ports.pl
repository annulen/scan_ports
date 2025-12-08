#!/usr/bin/env perl

use URI::Split qw(uri_split);
use strict;
use warnings;
use autodie;

my %hosts_by_port;

sub uri_scheme_ok {
    return shift eq 'socks5';
}

sub dump_hosts {
    local $" = ', ';
    while (my ($port, $hosts) = each %hosts_by_port) {
        print "$port: [ @$hosts ]\n";
    }
}

sub do_nmap_scan {
    my $port = shift;
    my @hosts = @_;

    open my $nmap, '-|', "nmap -n -Pn -oG - -p $port @hosts | grep -wF Ports:";
    while(<$nmap>) {
        if (my ($host, $port, $info) = m{^Host: ([.0-9]+).*Ports: (\d+)/(.*)}) {
            print "socks5://$host:$port\t$info\n";
        } else {
            warn "Could not parse nmap output: $_\n";
        }
    }
}

while(<>) {
    chomp;
    my ($scheme, $auth) = uri_split($_);
    next unless uri_scheme_ok($scheme);
    if (my ($host, $port) = $auth =~ /^(.*):(.*)$/) {
        push $hosts_by_port{$port}->@*, $host;
    } else {
        warn "Could not parse host:port pair from URI: $_\n";
    }
}

while (my ($port, $hosts) = each %hosts_by_port) {
    do_nmap_scan $port, @$hosts;
}

