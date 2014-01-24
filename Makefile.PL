require 5.008001;
use ExtUtils::MakeMaker;

my $requires = {
    'Encode' => 0,
    'Getopt::Long' => '2',
    'HTTP::Headers' => 0,
    'HTTP::Request' => 0,
    'LWP::UserAgent' => 0,
    'Test::More' => 0,
    'URI::URL' => 0,
    'Net::IDN::Punycode' => 1,
    'Regexp::IPv6' => 0,
    'File::Temp' => 0,
};
if ($^O =~ /Win/) {
  $requires->{'Win32API::Registry'} = 0;
}

WriteMakefile
(
          'NAME' => 'Net::Whois::Raw',
          'VERSION_FROM' => 'lib/Net/Whois/Raw.pm',
          'PREREQ_PM' => $requires,
          'INSTALLDIRS' => 'site',
          'EXE_FILES' => [
                           'pwhois'
                         ],
          'PL_FILES' => {}
        )
;
