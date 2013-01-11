#!/usr/bin/perl -w

use strict;

use Test::More tests => 23;

use_ok('Net::Whois::Raw');
use_ok('Net::Whois::Raw::Common');

ok( Net::Whois::Raw::Common::domain_level( 'reg.ru' )     == 2, 'domain_level' );
ok( Net::Whois::Raw::Common::domain_level(' www.reg.ru' ) == 3, 'domain_level' );

my ($name, $tld) = Net::Whois::Raw::Common::split_domain( 'reg.ru' );
ok( $name eq 'reg' && $tld eq 'ru', 'split_domain' );

($name, $tld) = Net::Whois::Raw::Common::split_domain( 'REG.RU' );
ok( $name eq 'REG' && $tld eq 'RU', 'split_domain');

($name, $tld) = Net::Whois::Raw::Common::split_domain( 'auto.msk.ru' );
ok( $name eq 'auto' && $tld eq 'msk.ru', 'split_domain' );

ok(  Net::Whois::Raw::Common::is_ipaddr( '122.234.214.214' ), 'is_ipaddr' );
ok( !Net::Whois::Raw::Common::is_ipaddr( 'a22.b34.214.214' ), 'is_ipaddr' );

ok(  Net::Whois::Raw::Common::is_ip6addr( '2002::2eb6:195b' ), 'is_ip6addr' );
ok( !Net::Whois::Raw::Common::is_ip6addr( '2002::2eb6:195g' ), 'is_ip6addr' );
ok(  Net::Whois::Raw::Common::is_ip6addr( '::ffff:c000:0280' ), 'is_ip6addr (ipv4)' );

ok( Net::Whois::Raw::Common::get_dom_tld( '125.214.84.1' )   eq 'IP',     'get_dom_tld' );
ok( Net::Whois::Raw::Common::get_dom_tld( 'REGRU-REG-RIPN' ) eq 'NOTLD',  'get_dom_tld' );
ok( Net::Whois::Raw::Common::get_dom_tld( 'yandex.ru' )      eq 'ru',     'get_dom_tld' );
ok( Net::Whois::Raw::Common::get_dom_tld( 'auto.msk.ru' )    eq 'msk.ru', 'get_dom_tld' );

ok( Net::Whois::Raw::Common::get_real_whois_query( 'sourceforge.net', 'whois.crsnic.net' )
    eq 'domain sourceforge.net', 'get_real_whois_query'
);
ok( Net::Whois::Raw::Common::get_real_whois_query( 'mobile.de', 'whois.denic.de' )
    eq '-T dn,ace -C ISO-8859-1 mobile.de', 'get_real_whois_query'
);
ok( Net::Whois::Raw::Common::get_real_whois_query( 'nic.name',  'whois.nic.name' )
    eq 'domain=nic.name', 'get_real_whois_query'
);
ok( Net::Whois::Raw::Common::get_real_whois_query( 'reg.ru',    'whois.ripn.net' )
    eq 'reg.ru', 'get_real_whois_query'
);

is( Net::Whois::Raw::Common::get_server( 'reg.ru' ), 'whois.ripn.net', 'get_server' );
is( Net::Whois::Raw::Common::get_server( 'nic.vn' ), 'www_whois',      'get_server' );
is( Net::Whois::Raw::Common::get_server( undef, undef, 'spb.ru' ), 'whois.nic.ru', 'get_server' );
