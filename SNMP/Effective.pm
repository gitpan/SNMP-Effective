
#=======================
package SNMP::Effective;
#=======================

use warnings;
use strict;
use SNMP;
use POSIX qw(:errno_h);
use vars qw/$DEBUG %METHOD %SNMPARG @ISA $VERSION/;

$VERSION = 1.0;
@ISA     = qw/SNMP::Effective::Var SNMP::Effective::Dispatch/;
$DEBUG   = 0;
%METHOD  = map { $_ => $_ } qw/get getnext set/;
%SNMPARG = (
    Version   => '2c',
    Community => 'public',
    Timeout   => 1e6,
    Retries   => 2
);


sub new { #===================================================================

    ### init
    my $class = shift;
    my %args  = @_;
    my $self  = (ref $class) ? $class : bless {
        MaxSessions    => $args{'MaxSessions'}   || 1,
        MasterTimeout  => $args{'MasterTimeout'},
        _sessions      => 0,
        _dispatch_lock => 0,
    }, $class;

    ### setup VarReq
    SNMP::Effective::Var::new($self, %args);

    ### the end
    return $self;
}

sub execute { #===============================================================

    ### init
    my $self           = shift;
    local $SIG{'ALRM'} = sub { $self->_timeout };

    SNMP::Effective::DEBUG("Start execute", 2);

    ### Dispatch
    alarm $self->{'MasterTimeout'} if($self->{'MasterTimeout'});
    $self->Dispatch() and SNMP::MainLoop();

    ### the end
    SNMP::Effective::DEBUG("End execute", 2);
}

sub _timeout { #==============================================================
    $_[0]->{'_dispatch_lock'} = 0;
    $_[0]->{'MasterTimeout'}  = 0;
    SNMP::Effective::DEBUG("Master Timeout", 2);
    SNMP::finish();
}

sub create_session { #========================================================

    ### init
    my $self = shift;
    my $host = shift;
    my $snmp;

    ### create session
    $!    = 0;
    $snmp = SNMP::Session->new(%SNMPARG, $host->Arg);

    ### check error
    unless($snmp) {
        my($retry, $msg) = $self->_check_errno($!);
        $self->error($msg);
        return ($retry) ? '' : undef;
    }

    ### the end
    return $snmp;
}

sub _check_errno { #==========================================================
    
    ### init
    my $err    = pop;
    my $retry  = 0;
    my $string = '';

    ### some strange error
    unless($!) {
        $string  = "Couldn't resolve hostname";
    }
        
    ### some other error
    else {
        $string = $! + '';
        if(
            $err == EINTR  ||  # Interrupted system call
            $err == EAGAIN ||  # Resource temp. unavailable
            $err == ENOMEM ||  # No memory (temporary)
            $err == ENFILE ||  # Out of file descriptors
            $err == EMFILE     # Too many open fd's
        ) {
            $string .= ' (will retry)';
            $retry   = 1;
        }
    }

    ### the end
    return($retry, $string);
}

sub DEBUG { #=================================================================

    ### init
    my $message = shift || '';
    my $level   = shift || 0;

    ### print warnings
    warn "debug($level): $message\n" if($level <= $DEBUG);
}

sub error { #=================================================================
    my $msg = $_[0]->{'error'};
    $_[0]->{'error'} = $_[1] if(defined $_[1]);
    return $msg;
}

sub matchOid { #==============================================================

    ### init
    local $_ = shift || return;
    my $match  = shift || return;
    
    ### check
    return /^\.?$match\.?(.*)/ ? $1 : undef;
}

sub makeNumericOid { #========================================================

    ### init
    local $_;
    my @input = @_;
    
    ### fix
    for(@input) {
        next if(/^[\d\.]+$/);
        $_ = SNMP::translateObj($_);
    }
    
    ### the end
    return wantarray ? @input : $input[0];
}

sub makeNameOid { #===========================================================

    ### init
    local $_;
    my @input = @_;
    
    ### fix
    for(@input) {
        $_ = SNMP::translateObj($_) if(/^[\d\.]+$/);
    }
    
    ### the end
    return wantarray ? @input : $input[0];

}


#=================================
package SNMP::Effective::Dispatch;
#=================================

use strict;
use Time::HiRes qw/usleep/;


sub _set { #==================================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;

    ### timeout
    unless(ref $response) {
        return $self->_end($host, 'timeout');
    }

    ### handle response
    for my $r (grep { ref $_ } @$response) {
        my $cur_oid = SNMP::Effective::makeNumericOid($r->name);
        $host->data($cur_oid, $cur_oid, $r->val);
    }

    ### the end
    $self->_end($host);
}

sub _get { #==================================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;

    ### timeout
    unless(ref $response) {
        return $self->_end($host, 'timeout');
    }

    ### handle response
    for my $r (grep { ref $_ } @$response) {
        my $cur_oid = SNMP::Effective::makeNumericOid($r->name);
        $host->data($cur_oid, $cur_oid, $r->val);
    }

    ### the end
    $self->_end($host);
}

sub _getnext { #==============================================================

    ### init
    my $self     = shift;
    my $host     = shift;
    my $request  = shift;
    my $response = shift;
    my $i        = 0;

    ### timeout
    unless(ref $response) {
        return $self->_end($host, 'timeout');
    }

    ### handle response
    while($i < @$response) {
        my $splice = 2;

        ### handle result
        if(my $r = $response->[$i]) {
            my($cur_oid, $ref_oid) = SNMP::Effective::makeNumericOid(
                $r->name, $request->[$i]->name
            );
            $r->[0] = $cur_oid;
            $splice--;

            ### valid oid
            if(defined SNMP::Effective::matchOid($cur_oid, $ref_oid)) {
                $host->data($ref_oid, $cur_oid, $r->val);
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
        $$host->getnext($response, [ \&_getnext, $self, $host, $request ]);
    }

    ### the end
    else {
        $self->_end($host);
    }
}

sub _end { #==================================================================

    ### init
    my $self  = shift;
    my $host  = shift;
    my $error = shift;

    ### cleanup
    $host->Callback->($host, $error);

    ### the end
    $self->Dispatch($host)
}

sub Dispatch { #==============================================================

    ### init
    my $self  = shift;
    my $host  = shift;
    my $_Host = $self->_Host;
    my $request;

    ### setup
    usleep 900 + int rand 200 while($self->{'_dispatch_lock'});
    $self->{'_dispatch_lock'} = 1;

    ### iterate host list
    while($self->{'_sessions'} < $self->{'MaxSessions'} or $host) {

        ### init
        $host  ||= shift @$_Host or last;
        $request = shift @$host;
        my $sess_id;

        ### test request
        next unless(ref $request);

        ### fetch or create snmp session
        unless($$host) {
            unless($$host = $self->create_session($host)) {
                SNMP::Effective::DEBUG('undef snmp: ' .$self->error(), 50);
                next;
            }
            $self->{'_sessions'}++;
        }

        ### ready request
        if($$host->can($request->[0]) and $self->can("_$request->[0]")) {
            no strict;
            $cb      = \&{__PACKAGE__ ."::_$request->[0]"};
            $method  = $request->[0];
            $sess_id = $$host->$method(
                $request->[1], [$cb, $self, $host, $request->[1]]
            );
            SNMP::Effective::DEBUG("$host -> $method : $request->[1]", 50);
        }

        ### something went wrong
        unless($sess_id) {
            SNMP::Effective::DEBUG("Method: $request->[0] failed \@ $host", 50);
            next;
        }
    }
    continue {
        if(ref $$host and !ref $request) {
            $self->{'_sessions'}--;
            SNMP::Effective::DEBUG("complete: $host", 150);
        }
        $host = undef;
    }

    ### the end
    $self->{'_dispatch_lock'} = 0;
    SNMP::Effective::DEBUG("$self->{'_sessions'} < $self->{'MaxSessions'}", 50);
    unless(@$_Host or $self->{'_sessions'}) {
        SNMP::Effective::DEBUG("SNMP::finish", 10);
        SNMP::finish();
    }

    ### the end
    return @$_Host || $self->{'_sessions'};
}


#================================
package SNMP::Effective::VarList;
#================================

use warnings;
use strict;
use Tie::Array;
use vars qw/@ISA/;
use constant METHOD => 0;
use constant OID    => 1;
use constant SET    => 2;

@ISA = qw/Tie::StdArray/;


sub PUSH { #==================================================================

    ### init
    my $self = shift;
    my $r    = shift;

    ### test request
    return unless(ref $r eq 'ARRAY' and $r->[METHOD] and $r->[OID]);
    return unless($SNMP::Effective::METHOD{$r->[METHOD]});

    ### fix OID array
    $r->[OID] = [$r->[OID]] unless(ref $r->[OID] eq 'ARRAY');

    ### setup VarList
    my @varlist = map  {
                      ref $_ eq 'ARRAY' ? $_    :
                      /([0-9\.]+)/      ? [$1]  :
                                          undef ;
                  } @{$r->[OID]};

    ### add elements
    push @$self, [
                     $r->[METHOD],
                     SNMP::VarList->new( grep $_, @varlist ),
                 ];
}


#=============================
package SNMP::Effective::Host;
#=============================

use warnings;
use strict;
use overload '""'  => sub { $_[0]->{'Addr'}    };
use overload '${}' => sub { $_[0]->{'Session'} };
use overload '@{}' => sub { $_[0]->{'VarList'} };
use vars qw/$AUTOLOAD/;


sub data { #==================================================================

    ### init
    my $self = shift;

    ### save data
    if(@_) {
        
        ### init save
        my $ref_oid = shift || '';
        my $cur_oid = shift || '';
        my $data    = shift || '';
        my $iid     = SNMP::Effective::matchOid($cur_oid, $ref_oid) || 1;

        $ref_oid    =~ s/^\.//;

        ### save
        $self->{'data'}{$ref_oid}{$iid} = $data;
    }

    ### the end
    $self->{'data'};
}

sub Arg { #===================================================================

    ### init
    my $self = shift;
    my $arg  = shift;

    ### set value
    if(ref $arg eq 'HASH') {
        $self->{'Arg'}{$_} = $arg->{$_} for(keys %$arg);
    }

    ### the end
    return wantarray ? (%{$self->{'Arg'}}, DestHost => "$self") : ();
}

sub new { #===================================================================
    
    ### init
    my $class = shift;
    my $addr  = shift || return;
    my %args  = @_;
    my($session, @VarList);

    ### tie
    tie @VarList, "SNMP::Effective::VarList";

    ### the end
    return bless {
        Addr     => $addr,
        Session  => \$session,
        VarList  => \@VarList,
        Callback => sub {},
        Arg      => {},
        data     => {},
        %args,
    }, $class;
}

sub AUTOLOAD { #==============================================================
    
    ### init
    my $self  = shift;
    my($key)  = $AUTOLOAD =~ /::(\w+)$/;
    my $value = shift;

    ### set data
    if(exists $self->{$key}) {
        $self->{$key} = $value if(ref $value eq ref $self->{$key});
        return $self->{$key};
    }
}


#=================================
package SNMP::Effective::HostList;
#=================================

use warnings;
use strict;
use overload '@{}' => \&HostArray;


sub TIEARRAY { #==============================================================
    return $_[1];
}

sub FETCHSIZE { #=============================================================
    return scalar keys %{$_[0]};
}

sub SHIFT { #=================================================================
    my $self = shift;
    my $key  = (keys %$self)[0] or return;
    return delete $self->{$key};
}

sub HostArray { #=============================================================
    my @Array;
    tie @Array, ref $_[0], $_[0];
    return \@Array;
}

sub new { #===================================================================
    bless {}, $_[0];
}


#============================
package SNMP::Effective::Var;
#============================

use warnings;
use strict;
use SNMP;
use vars qw/@ISA $AUTOLOAD/;


sub add { #===================================================================

    ### init
    my $self     = shift;
    my %in       = @_;
    my $_Host    = $self->_Host;
    my $_VarList = $self->_VarList;
    my $VarList  = [];

    ### setup host
    if($in{'DestHost'} and ref $in{'DestHost'} ne 'ARRAY') {
        $in{'DestHost'} = [$in{'DestHost'}];
    }

    ### setup varlist
    for my $key (keys %SNMP::Effective::METHOD) {
        push @$VarList, [$key, $in{$key}] if($in{$key});
    }
    unless(@$VarList) {
        $VarList = $_VarList;
    }

    ### DEBUG
    SNMP::Effective::DEBUG("Vars: " .scalar @$VarList, 50);

    ### add new hosts
    if(ref $in{'DestHost'} eq 'ARRAY') {
        for my $addr (@{$in{'DestHost'}}) {
            
            ### create new host
            unless($_Host->{$addr}) {
                $_Host->{$addr} = SNMP::Effective::Host->new($addr);
                $_Host->{$addr}->Arg($self->{'Arg'});
                $_Host->{$addr}->Callback($self->{'Callback'});
            }

            ### alter created/existing host
            push @{$_Host->{$addr}}, @$VarList;
            $_Host->{$addr}->Arg($in{'Arg'});
            $_Host->{$addr}->Callback($in{'Callback'});
        }

        local $" = ", ";
        SNMP::Effective::DEBUG("Added @{$in{'DestHost'}}", 180);
    }

    ### update hosts
    else {
        push @$_VarList, @$VarList;
        $self->Arg($in{'Arg'});
        $self->Callback($in{'Callback'});
    }
}

sub new { #===================================================================
    
    ### init
    my $self = shift;

    ### fix self
    $self->{'_Host'}    = SNMP::Effective::HostList->new();
    $self->{'_VarList'} = [];
    $self->{'Arg'}      = {};
    $self->{'Callback'} = sub {};

    ### add data
    add($self, @_) if(@_ > 1);
}

sub AUTOLOAD { #==============================================================
    
    ### init
    my $self  = shift;
    my($key)  = $AUTOLOAD =~ /::(\w+)$/;
    my $value = shift;

    ### set/get data
    if(exists $self->{$key}) {
        $self->{$key} = $value if(ref $value eq ref $self->{$key});
        return $self->{$key};
    }

    ### the end
    return;
}

#=============================================================================
1983;
