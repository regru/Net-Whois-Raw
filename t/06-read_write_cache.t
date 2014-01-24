#!/usr/bin/perl -w

use strict;
use warnings;
use utf8;
use Test::More tests => 2;
use Net::Whois::Raw::Common;
use File::Temp qw/tempdir/;

my $temp = tempdir("__Net_Whois_Raw_${$}_XXXXXXXX", TMPDIR => 1, CLEANUP => 1);
my @expected = ("some result", "wide русский текст", "latin1 μ");
my $data = [map { {text => $_} } @expected];
Net::Whois::Raw::Common::write_to_cache('test.com', $data, $temp);
my $r = Net::Whois::Raw::Common::get_from_cache('test.com', $temp, 10);
my @got = map { $_->{text} } @{ $r };
is_deeply \@got, \@expected, "should read from cache right";
my @got2 = map { $_->{text} } @{ $data };
is_deeply \@got2, \@expected, "should not damage cache";
