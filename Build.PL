#!/usr/bin/perl -w
use strict;
use Module::Build;

my $requires = {
    'perl' => '5.008001',
    'Getopt::Long' => 2.0,
    'URI::URL' => 0,
    'LWP::UserAgent' => 0,
    'HTTP::Request' => 0,
    'HTTP::Headers' => 0,
    'Test::More' => 0,
    'Encode' => 0,
    'Net::IDN::Punycode' => 1,
    'Regexp::IPv6' => 0,
    'File::Temp' => 0,
};

if ($^O =~ /Win/) {
    $requires->{'Win32API::Registry'} = 0;
}
my $build = Module::Build->new(
    module_name => 'Net::Whois::Raw',
    license  => 'perl',
    requires => $requires,
    script_files => 'pwhois',
    dist_abstract => 'Get Whois information for domains',
);

$build->create_build_script;

# IS IT NECESSARY? (see belowe)
#
#sub MY::postamble {
#        package MY;
#        shift->SUPER::postamble . <<'MAKE';
#dist : README
#
#README : lib/Net/Whois/Raw.pm
#	@$(PERL) -MPod::Text -e "pod2text('$<');" > $@
#
#MAKE
#}
