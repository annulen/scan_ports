#!/usr/bin/env perl

use Parallel::ForkManager;
use URI::Split qw(uri_split);
use Sys::CPU;

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
    my @logs;

    open my $nmap, '-|', "nmap -n -Pn -oG - -p $port @hosts | grep -wF Ports:";
    while(<$nmap>) {
        my $log;
        if (my ($host, $port, $info) = m{^Host: ([.0-9]+).*Ports: (\d+)/(.*)}) {
            $log = "socks5://$host:$port\t$info\n";
        } else {
            $log = "Could not parse nmap output: $_\n";
        }
        push @logs, $log;
    }
    return \@logs;
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

my @logs;

my $pm = Parallel::ForkManager->new(Sys::CPU::cpu_count());
$pm->run_on_finish(sub {
    my $retrieved = $_[5];
    push @logs, @$retrieved;
});
$pm->set_waitpid_blocking_sleep(0);  # true blocking calls enabled

while (my ($port, $hosts) = each %hosts_by_port) {
    $pm->start and next;
    my $r = do_nmap_scan $port, @$hosts;
    $pm->finish(0, $r);
}
$pm->wait_all_children;

print @logs;
