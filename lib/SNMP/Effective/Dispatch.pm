
#=================================
package SNMP::Effective::Dispatch;
#=================================

use strict;
use warnings;
use Time::HiRes qw/usleep/;

our $VERSION = '1.05';
our %METHOD  = (
    get     => 'get',
    getnext => 'getnext',
    walk    => 'getnext',
    set     => 'set',
);


sub _set { #==================================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;

    ### timeout
    return $self->_end($host, 'Timeout') unless(ref $response);

    ### handle response
    for my $r (grep { ref $_ } @$response) {
        my $cur_oid = SNMP::Effective::make_numeric_oid($r->name);
        $host->data($r, $cur_oid);
    }

    ### the end
    return $self->_end($host);
}

sub _get { #==================================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;

    ### timeout
    return $self->_end($host, 'Timeout') unless(ref $response);

    ### handle response
    for my $r (grep { ref $_ } @$response) {
        my $cur_oid = SNMP::Effective::make_numeric_oid($r->name);
        $host->data($r, $cur_oid);
    }

    ### the end
    return $self->_end($host);
}

sub _getnext { #==============================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;

    ### timeout
    return $self->_end($host, 'Timeout') unless(ref $response);

    ### handle response
    for my $r (grep { ref $_ } @$response) {
        my $cur_oid = SNMP::Effective::make_numeric_oid($r->name);
        $host->data($r, $cur_oid);
    }

    ### the end
    return $self->_end($host);
}

sub _walk { #=================================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;
    my $i        = 0;

    ### timeout
    return $self->_end($host, 'Timeout') unless(ref $response);

    ### handle response
    while($i < @$response) {
        my $splice = 2;

        ### handle result
        if(my $r = $response->[$i]) {
            my($cur_oid, $ref_oid) = SNMP::Effective::make_numeric_oid(
                                         $r->name, $request->[$i]->name
                                     );
            $r->[0] = $cur_oid;
            $splice--;

            ### valid oid
            if(defined SNMP::Effective::match_oid($cur_oid, $ref_oid)) {
                $host->data($r, $ref_oid);
                $splice--;
                $i++;
            }
        }

        ### bad result
        if($splice) {
            splice @$request, $i, 1;
            splice @$response, $i, 1;
        }
    }

    ### to be continued
    if(@$response) {
        $$host->getnext($response, [ \&_walk, $self, $host, $request ]);
        return;
    }

    ### no more to get
    else {
        return $self->_end($host);
    }
}

sub _end { #==================================================================

    ### init
    my $self  = shift;
    my $host  = shift;
    my $error = shift;

    ### cleanup
    $self->log->debug("Calling callback for $host...");
    $host->callback->($host, $error);
    $host->clear_data;

    ### the end
    return $self->dispatch($host)
}

sub dispatch { #==============================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $hostlist = $self->hostlist;
    my $log      = $self->log;
    my $request;
    my $req_id;

    ### setup
    usleep 900 + int rand 200 while($self->_lock);
    $self->_lock(1);

    HOST:
    while($self->{'_sessions'} < $self->max_sessions or $host) {

        ### init
        $host         ||= shift @$hostlist or last HOST;
        $request        = shift @$host     or next HOST;
        $req_id         = undef;
        my $snmp_method = $METHOD{ $request->[0] };

        ### fetch or create snmp session
        unless($$host) {
            unless($$host = $self->_create_session($host)) {
                next HOST;
            }
            $self->{'_sessions'}++;
        }

        ### ready request
        if($$host->can($snmp_method) and $self->can("_$request->[0]")) {
            $req_id = $$host->$snmp_method(
                          $request->[1],
                          [ "_$request->[0]", $self, $host, $request->[1] ]
                      );
            $log->debug(
                "\$self->_$request->[0]( ${host}->$snmp_method(...) )"
            );
        }

        ### something went wrong
        unless($req_id) {
            $log->info("Method $request->[0] failed \@ $host");
            next HOST;
        }
    }
    continue {
        if(ref $$host and !ref $request) {
            $self->{'_sessions'}--;
            $log->info("Completed $host");
        }
        if($req_id or !@$host) {
            $host = undef;
        }
    }

    ### the end
    $self->_lock(0);
    $log->debug(
        "Sessions/max-sessions: "
       .$self->{'_sessions'} ." < " .$self->max_sessions
    );
    unless(@$hostlist or $self->{'_sessions'}) {
        $log->info("SNMP::finish() is next up");
        SNMP::finish();
    }

    ### the end
    return @$hostlist || $self->{'_sessions'};
}

#=============================================================================
1983;
__END__

=head1 NAME

SNMP::Effective::Dispatch - Helper module for SNMP::Effective

=head1 VERSION

This document refers to version 1.05 of SNMP::Effective::Dispatch.

=head1 DESCRIPTION

This is a helper module for SNMP::Effective

=head1 METHODS

=head2 C<dispatch>

This method does the actual fetching, and is called by
SNMP::Effective::execute

=head1 DEBUGGING

Debugging is enabled through Log::Log4perl. If nothing else is spesified,
it will default to "error" level, and print to STDERR. The component-name
you want to change is "SNMP::Effective", inless this module ins inherited.

=head1 NOTES

=head2 %SNMP::Effective::Dispatch::METHOD

This hash contains a mapping between $effective->add($key => []),
SNMP::Effective::Dispatch::_$key() and SNMP.pm's $value method. This means
that you can actually add your custom method if you like.

The SNMP::Effective::Dispatch::_walk() method, is a working example on this,
since it's actually a series of getnext, seen from SNMP.pm's perspective.

=head1 TODO

=head1 AUTHOR

Jan Henning Thorsen, C<< <pm at flodhest.net> >>

=head1 ACKNOWLEDGEMENTS

Various contributions by Oliver Gorwits.

=head1 COPYRIGHT & LICENSE

Copyright 2007 Jan Henning Thorsen, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

