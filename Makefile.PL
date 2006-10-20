
use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'         => 'SNMP::Effective',
    'VERSION_FROM' => 'SNMP/Effective.pm', # finds $VERSION
    'dist'         => { COMPRESS => 'gzip', SUFFIX=>'gz' },
    'PREREQ_PM'    => {
         'SNMP' => '5.2',
     },
);

