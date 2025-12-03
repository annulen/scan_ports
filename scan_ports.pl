#!/usr/bin/env perl

use URI;
use URI::Split qw(uri_split);
use strict;
use warnings;

while(<>) {
    #my @p = uri_split($_);
    #print "@p\n";
    #my $u = URI->new($_);
    chomp;
    my ($scheme, $auth) = uri_split($_);
    unless ($scheme eq 'socks5') {
        print "Not socks5 URI detected: $scheme://$auth\n";
        next;
    }
    my ($host, $port) = $auth =~ /^(.*):(.*)$/;
    system("nmap -Pn -oG - -p '$port' '$host' | grep Ports:");
}
