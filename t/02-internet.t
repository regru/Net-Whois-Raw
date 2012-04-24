#!/usr/bin/perl -w

use strict;

use Data::Dumper;
use Test::More tests => 10;

BEGIN {
    use_ok('Net::Whois::Raw',qw( whois ));

    $Net::Whois::Raw::CHECK_FAIL = 1;
    $Net::Whois::Raw::OMIT_MSG = 1;
    $Net::Whois::Raw::CHECK_EXCEED = 1;
};

my @domains = qw(
    yahoo.com
    freebsd.org
    reg.ru
    ns1.nameself.com.NS
    XN--C1AD6A.XN--P1AI
);

SKIP: {
    print "The following tests requires internet connection. Checking...\n";
    skip "Looks like no internet connection", 
        Test::More->builder->expected_tests() - 1 unless get_connected();
    
    # registrars    
    like( whois( 'REGRU-REG-RIPN', 'whois.ripn.net' ), qr/www.reg.ru/ );
    
    # domains    
    foreach my $domain ( @domains ) {
        my $txt = whois( $domain );
        $domain =~ s/.NS$//i;
        ok($txt && $txt =~ /$domain/i, "$domain resolved");
    }
    
    # Net::Whois::Raw::www_whois_query for AC domain
    # ok( Net::Whois::Raw::www_whois_query( 'nic.ac' ) =~ /Organization Name.*Network Information Center/i, "www_whois_query");
    
    # Net::Whois::Raw::Common::process_whois
    no warnings;
    $Net::Whois::Raw::CHECK_FAIL   = 0;
    $Net::Whois::Raw::OMIT_MSG     = 0;
    $Net::Whois::Raw::CHECK_EXCEED = 0;

    my $whois = whois('reg.ru');
    my ($processed) = Net::Whois::Raw::Common::process_whois( 'reg.ru', 'whois.ripn.net', $whois, 2, 2, 2 );
    ok( length( $processed ) < length( $whois ) && $processed =~ /reg\.ru/, 'process_whois' );
    
    # Net::Whois::Raw::Common::write_to_cache
    my $test_domain = 'google.com';
    my $tmp_dir;
    if ($^O =~ /mswin/i) {
        $tmp_dir = $ENV{TEMP}.'\net-whois-raw-common-test-'.time;
    }
    else {
        $tmp_dir = '/tmp/net-whois-raw-common-test-'.time;
    }
    my $cache_file  = "$tmp_dir/$test_domain.00";
    
    $Net::Whois::Raw::CACHE_DIR = $tmp_dir;
    $whois = whois( $test_domain, undef, 'QRY_FIRST' );
    ok( -e $cache_file, 'write_to_cache' );
    
    # Net::Whois::Raw::Common::get_from_cache
    open CACHE, ">>$cache_file";
    print CACHE "net-whois-raw-common-test";
    close CACHE;
    
    like( whois( $test_domain, undef, 'QRY_FIRST' ), qr/net-whois-raw-common-test/s, 'get_from_cache' );

    unlink <$tmp_dir/*>;
    rmdir $tmp_dir;
};

sub get_connected {
    require LWP::UserAgent;
    my $ua = LWP::UserAgent->new( timeout => 10 );
    my $res = $ua->get( 'http://www.google.com' );
    
    return $res->is_success;
}

