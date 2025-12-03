#!/usr/bin/env perl

use URI::Split qw(uri_split);
use strict;
use warnings;

my %hosts_by_port;

sub dump_hosts {
    local $" = ', ';
    while (my ($port, $hosts) = each %hosts_by_port) {
        print "$port: [ @$hosts ]\n";
    }
}

sub do_scan {
    my $port = shift;
    my @hosts = @_;

    my $cmd = "nmap -Pn -oG - -p $port @hosts | grep -wF Ports:";
    system($cmd) == 0 or die "nmap failed: $!";
}

while(<>) {
    chomp;
    my ($scheme, $auth) = uri_split($_);
    next if $scheme !~ /^socks/;
    my ($host, $port) = $auth =~ /^(.*):(.*)$/;
    push $hosts_by_port{$port}->@*, $host;
}

while (my ($port, $hosts) = each %hosts_by_port) {
    do_scan $port, @$hosts;
}

