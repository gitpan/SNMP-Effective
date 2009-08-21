package SNMP::Effective::Utils;

=head1 NAME

SNMP::Effective::Utils - Utils for SNMP::Effective

=head1 SYNOPSIS

 use SNMP::Effective::Utils;
 #...

=cut 

use Moose;
use SNMP;

=head1 FUNCTIONS

=head2 match_oid

 match_oid("1.3.6.10",   "1.3.6");    # return 10
 match_oid("1.3.6.10.1", "1.3.6");    # return 10.1
 match_oid("1.3.6.10",   "1.3.6.11"); # return undef

Takes two arguments: One OID to match against, and the OID to match.

=cut

sub match_oid {
    my $p = shift or return;
    my $c = shift or return;
    return ($p =~ /^ \.? $c \.? (.*)/mx) ? $1 : undef;
}

=head2 make_numeric_oid

 make_numeric_oid("sysDescr"); # return .1.3.6.1.2.1.1.1 

Inverse of make_numeric_oid: Takes a list of mib-object strings, and turns
them into numeric format.

=cut

sub make_numeric_oid {
    my @input = @_;
    
    for my $i (@input) {
        next if($i =~ /^ [\d\.]+ $/mx);
        $i = SNMP::translateObj($i);
    }
    
    return wantarray ? @input : $input[0];
}

=head2 make_name_oid

 make_name_oid("1.3.6.1.2.1.1.1"); # return sysDescr

Takes a list of numeric OIDs and turns them into an mib-object string.

=cut

sub make_name_oid {
    my @input = @_;
    
    # fix
    for my $i (@input) {
        $i = SNMP::translateObj($i) if($i =~ /^ [\d\.]+ $/mx);
    }
    
    return wantarray ? @input : $input[0];

}

=head1 BUGS

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

=head1 AUTHOR

See L<SNMP::Effective>.

=cut

1;
