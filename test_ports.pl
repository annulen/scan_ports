#!/usr/bin/env perl

use IO::Socket::SSL;
use Net::SSLeay;
use URI::Split qw(uri_split);

use strict;
use warnings;

sub check_cert {
    my ($host, $port) = @_;
    print "----> $host $port\n";
    #    my $sock = IO::Socket::SSL->new(
    #        PeerAddr => $host,
    #        PeerPort => $port,
    #        Timeout => 30,
    #    );
}

while(<>) {
    print;
    my ($url) = split ' ';
    my ($scheme, $auth) = uri_split($url);
    if (my ($host, $port) = $auth =~ /^(.*):(.*)$/) {
        check_cert($host, $port);
    } else {
        warn "Could not parse host:port pair from URI: $_\n";
    }
}
