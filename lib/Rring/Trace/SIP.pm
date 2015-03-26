
package Rring::Trace::SIP;

use Moose;
use Net::Frame::Dump::Offline;
use Net::Frame::Simple;
use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;

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

has 'out_call_id' =>
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

has 'out_sip_packets' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
    );

has 'out_packet_timestamps' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
    );

has 'out_call_props' =>
    (
     is  => 'rw',
     isa => 'HashRef',
     init_arg => undef,
     default => sub { {} },
    );

has 'out_call_errors' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
     default => sub { [] },
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
    else
    {
        push(@cmd, '-i', 'any');
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

    sleep(5);
    $log->debug('Started capture: ' . join(' ', @cmd));
    $self->tcpdump_pid($pid);

    return;
}


sub stop
{
    my $self = shift;
    
    sleep(5);
    my $pid = $self->tcpdump_pid;
    kill('TERM', $pid);
    waitpid($pid, 0);
    $log->debug('Capture stopped');
    $self->session_id('');
    return;    
}


sub analyze_outbound_call
{
    my $self = shift;

    my $callid = $self->out_call_id;
    if( $callid eq '' )
    {
        die("out_call_id is empty, cannot analyze");
    }

    my $sip_packets = [];
    my $timestamps = [];
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

        my $payload = $f->ref->{'UDP'}->payload;
        # $log->debug($payload);
        my $pkt = eval { Net::SIP::Packet->new($payload) };
        if( defined($pkt) )
        {
            if( $pkt->callid eq $callid )
            {
                push(@{$sip_packets}, $pkt);
                push(@{$timestamps}, $h->{timestamp});
            }
        }
        else
        {
            $log->warn("Capture caught a non-SIP packet");
        }
    }
    
    $oDump->stop;

    if( scalar(@{$sip_packets}) == 0 )
    {
        die('Capture does not have SIP packets for Call-ID ' . $callid);
    }
    
    $self->out_sip_packets($sip_packets);
    $self->out_packet_timestamps($timestamps);

    my $props = $self->out_call_props;
    my $errors = $self->out_call_errors;
    
    # analyze the call flow
    my $i = 0;
    my $invite_cseq;
    
    # analyze the first INVITE
    {
        my $pkt = $sip_packets->[$i];        
        if( not $pkt->is_request or $pkt->method ne 'INVITE')
        {
            die('First packet in the call is not INVITE');
        }

        $invite_cseq = $pkt->cseq;
        
        my $sdp = eval { $pkt->sdp_body };
        if( defined($sdp) )
        {
            $props->{'first_invite_has_sdp'} = 1;
            $props->{'invite_has_sdp'} = 1;
        }
    }

    
    my ($invite_cseq_num, $dummy) = split(/\s+/, $invite_cseq);
    
    my $invite_got_final_response = 0;
    my $call_connected = 0;
    my $auth_requested = 0;
    my $auth_sent = 0;
    
    while( not $invite_got_final_response and
           ++$i < scalar(@{$sip_packets}) )
    {
        my $pkt = $sip_packets->[$i];

        if( $pkt->is_request and $pkt->method eq 'INVITE' )
        {
            $invite_cseq = $pkt->cseq;
            my ($new_invite_cseq_num, $dummy) = split(/\s+/, $invite_cseq);
            if( $new_invite_cseq_num == $invite_cseq_num )
            {
                push(@{$errors}, 'INVITE ' . $invite_cseq_num .
                     ' was retransmitted');
                $props->{'invite_timeout'} = 1;
            }
            else
            {
                $invite_cseq_num = $new_invite_cseq_num;
                if( $auth_requested )
                {
                    if( scalar($pkt->get_header('Authorization')) or
                        scalar($pkt->get_header('Proxy-Authorization')) )
                    {
                        $auth_sent = 1;
                    }
                }
            }

            my $sdp = eval { $pkt->sdp_body };
            if( defined($sdp) )
            {
                $props->{'invite_has_sdp'} = 1;
            }
            next;
        }

        if( $pkt->is_request and $pkt->method eq 'CANCEL' )
        {
            $props->{'call_canceled'} = 1;
            last;
        }

        if( $pkt->is_request and $pkt->method eq 'ACK' )
        {
            next;
        }
        
        if( not $pkt->is_response or $pkt->cseq ne $invite_cseq )
        {
            push(@{$errors}, 'INVITE was not replied');
            last;
        }

        my $code = int($pkt->code);
        
        if( $code == 401 or $code == 407 )
        {
            if( scalar($pkt->get_header('WWW-Authenticate')) or
                scalar($pkt->get_header('Proxy-Authenticate')) )
            {
                $auth_requested = 1;
                $props->{'auth_requested'} = 1;
            }
            next;
        }
        
        if( $code >= 100 and $code <= 199 )
        {
            # session progress
            $props->{'progress_' . $code} = 1;
            if( not $auth_requested )
            {
                $props->{'unauth_progress_' . $code} = 1;
            }
            else
            {
                $props->{'auth_progress_' . $code} = 1;
            }

            if( $code == 183 )
            {
                my $sdp = eval { $pkt->sdp_body };
                if( defined($sdp) )
                {
                    $props->{'183_has_sdp'} = 1;
                }
            }
            next;
        }
        
        if( $code == 200 )
        {
            my $sdp = eval { $pkt->sdp_body };
            if( defined($sdp) )
            {
                $props->{'200_has_sdp'} = 1;
            }

            $invite_got_final_response = 1;
            $props->{'call_connected'} = 1;
            $call_connected = 1;
            next;
        }

        if( $code > 200 )
        {
            $invite_got_final_response = 1;
            $props->{'call_failed'} = 1;
            $props->{'failure_code'} = $code;
            $props->{'failure_msg'} = $pkt->msg;
        }
    }

    # process the rest of the call 
    while( $call_connected and 
           ++$i < scalar(@{$sip_packets}) )
    {
        my $pkt = $sip_packets->[$i];
        
        if( $pkt->is_request )
        {
            if( $pkt->method eq 'BYE' )
            {
                $call_connected = 0;
                $props->{'call_ended_normally'} = 1;
            }
        }
    }
    
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
