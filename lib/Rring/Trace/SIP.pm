
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

has 'call_id' =>
    (
     is  => 'rw',
     isa => 'Str',
     default => '',
    );

has 'invite_hdr_name' =>
    (
     is  => 'rw',
     isa => 'Str',
     default => '',
    );

has 'invite_hdr_value' =>
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

has 'sip_packets' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
    );

has 'packet_timestamps' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
    );

has 'packet_from_caller' =>
    (
     is  => 'rw',
     isa => 'ArrayRef',
     init_arg => undef,
    );


has 'caller_ipaddr' =>
    (
     is  => 'rw',
     isa => 'Str',
     init_arg => undef,
    );

has 'caller_udpport' =>
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


    my @cmd = ($Rring::tcpdump, '-q', '-B', '4096', '-w', $pcap);
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


sub _read_trace_file
{
    my $self = shift;

    my $callid = $self->call_id;
    my $invite_hdr_name = $self->invite_hdr_name;
    my $invite_hdr_value = $self->invite_hdr_value;

    if( $callid eq '' )
    {
        if( $invite_hdr_name eq '' )
        {
            die('invite_hdr_name cannot be empty when call_id is empty');
        }
        if( $invite_hdr_value eq '' )
        {
            die('invite_hdr_value cannot be empty when call_id is empty');
        }
    }    
        
    my $sip_packets = [];
    my $timestamps = [];
    my $packet_from_caller = [];
    
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
            my $srcaddr;
            if( defined($f->ref->{'IPv4'}) )
            {
                $srcaddr = $f->ref->{'IPv4'}->src;
            }
            elsif( defined($f->ref->{'IPv6'}) )
            {
                $srcaddr = $f->ref->{'IPv6'}->src;
            }
            else
            {
                die('Cannot determine sender IPv4/IPv6 address');
            }
            
            my $srcport = $f->ref->{'UDP'}->src;
            
            my $take = 0;
            if( $pkt->is_request and $pkt->method eq 'INVITE' )
            {
                if( $callid eq '' )
                {
                    if( $pkt->get_header($invite_hdr_name) =~
                        $invite_hdr_value )
                    {
                        $callid = $pkt->callid;
                        $self->call_id($callid);
                        $take = 1;
                    }
                }
                elsif( $pkt->callid eq $callid )
                {
                    $take = 1;
                }

                if( $take )
                {
                    $self->caller_ipaddr($srcaddr);
                    $self->caller_udpport($srcport);
                }                        
            }
            else
            {
                if( $callid ne '' and $pkt->callid eq $callid )
                {
                    $take = 1;
                }
            }
            
            if( $take )
            {
                push(@{$sip_packets}, $pkt);
                push(@{$timestamps}, $h->{timestamp});
                my $from_caller = 0;
                if( $self->caller_ipaddr eq $srcaddr and
                    $self->caller_udpport == $srcport )
                {
                    $from_caller = 1;
                }
                push(@{$packet_from_caller}, $from_caller);
            }
        }
        else
        {
            $log->warn("Capture caught a non-SIP packet");
        }
    }
    
    $oDump->stop;
    $self->sip_packets($sip_packets);
    $self->packet_timestamps($timestamps);
    $self->packet_from_caller($packet_from_caller);
    
    return;
}

    
sub analyze_call
{
    my $self = shift;

    $self->_read_trace_file();
    
    my $sip_packets = $self->sip_packets;
    
    my $props = {};
    my $errors = [];
    
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

        $props->{'invite_uri'} = $pkt->uri;
        $props->{'invite_from'} = $pkt->get_header('From');
        $props->{'invite_to'} = $pkt->get_header('To');
        my $pai = $pkt->get_header('P-Asserted-Identity');
        $props->{'invite_pai'} = $pai if defined($pai);
        my $privacy = $pkt->get_header('Privacy');
        $props->{'invite_privacy'} = $privacy if defined($privacy);
        
        my $sdp = eval { $pkt->sdp_body };
        if( defined($sdp) )
        {
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
                $props->{'call_ended_by_caller'} =
                    $self->packet_from_caller->[$i];
            }
        }
    }
    
    return ($props, $errors);
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
