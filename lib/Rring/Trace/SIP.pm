
package Rring::Trace::SIP;

use Moose;

has 'tester' =>
    (
     is  => 'rw',
     isa => 'Object',
     required => 1,
    );


has 'session_id' =>
    (
     is  => 'rw',
     isa => 'Str',
     init_arg => undef,
    );


has 'trace_file' =>
    (
     is  => 'rw',
     isa => 'Str',
     init_arg => undef,
    );
    

has 'tcpdump_pid' =>
    (
     is  => 'rw',
     isa => 'Int',
     init_arg => undef,
    );


sub start
{
    my $self = shift;
    my $session = shift;

    if( defined($self->session_id) )
    {
        die('Cannot start more than one trace session');
    }

    $self->session_id($session);

    my $cfg = $self->tester->cfg;

    my $dir = $cfg->{'trace_dir'};
    $dir = '/var/tmp' unless defined($dir);

    my $pcap = $dir . '/' . $session . '.pcap';
    $self->trace_file($pcap);
}


sub stop
{
    my $self = shift;
}
    

    
1;



# Local Variables:
# mode: cperl
# indent-tabs-mode: nil
# cperl-indent-level: 4
# cperl-continued-statement-offset: 4
# cperl-continued-brace-offset: -4
# cperl-brace-offset: 0
# cperl-label-offset: -2
# End:
