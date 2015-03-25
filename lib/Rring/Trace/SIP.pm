
package Rring::Trace::SIP;

use Moose;
use Net::Frame::Dump::Offline;
use Net::Frame::Simple;
use Net::SIP::Packet;

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

has 'call_id' =>
    (
     is  => 'rw',
     isa => 'Str',
     default => '',
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

our $log = Log::Any->get_logger;

sub start
{
    my $self = shift;
    my $session = shift;

    if( $self->session_id )
    {
        die('Cannot start more than one trace session');
    }

    $self->session_id($session);

    my $cfg = $self->tester->cfg;

    my $dir = $cfg->{'trace_dir'};
    $dir = '/var/tmp' unless defined($dir);

    my $pcap = $dir . '/' . $session . '.pcap';
    $self->trace_file($pcap);


    my @cmd = ($Rring::tcpdump, '-q', '-s', '0', '-w', $pcap);
    if( defined($cfg->{'pcap_iface'}) )
    {
        push(@cmd, '-i', $cfg->{'pcap_iface'});
    }

    my $filter = $cfg->{'pcap_filter'};
    $filter = 'udp port 5060' unless defined($filter);
    push(@cmd, $filter);
    
       
    my $pid = fork();
    if( not defined($pid) )
    {
        die("Cannot fork: $!");
    }
    elsif( $pid == 0 )
    {
        exec(@cmd);
    }

    $log->debug('Started capture: ' . join(' ', @cmd));
    $self->tcpdump_pid($pid);
    
    return;
}


sub stop
{
    my $self = shift;

    my $pid = $self->tcpdump_pid;
    kill('TERM', $pid);
    waitpid($pid, 0);
    $log->debug('Capture stopped');
    $self->session_id('');
    return;    
}


sub analyze
{
    my $self = shift;

    if( $self->call_id eq '' )
    {
        die("call_id is empty, cannot analyze");
    }

    my $oDump = Net::Frame::Dump::Offline->new('file' => $self->trace_file);

    $oDump->start;

    while( my $h = $oDump->next )
    {
        my $f = Net::Frame::Simple->new
            (
             raw        => $h->{raw},
             firstLayer => $h->{firstLayer},
             timestamp  => $h->{timestamp},
            );

        my $pkt = eval { Net::SIP::Packet->new($f->ref->{'UDP'}->payload) }
            or die "invalid SIP packet";

        
    }

    $oDump->stop;

    return;
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
