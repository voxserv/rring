
package Rring::Caller::FreeSWITCH;

use Moose;
use ESL;
use Log::Any;
use Time::HiRes qw(usleep);

has 'tester' =>
    (
     is  => 'rw',
     isa => 'Object',
     required => 1,
    );

has 'esl' =>
    (
     is  => 'rw',
     isa => 'Ref',
     init_arg => undef,
    );

our $log = Log::Any->get_logger;

sub BUILD
{
    my $self = shift;

    my $cfg = $self->tester->cfg;

    my %fsparam =
        (
         'fs_host' => '127.0.0.1',
         'fs_port' => '8021',
         'fs_password' => 'ClueCon',
        );

    foreach my $p (keys %fsparam)
    {
        if( defined($cfg->{$p}) )
        {
            $fsparam{$p} = $cfg->{$p};
        }
    }
    
    my $esl = new ESL::ESLconnection
        ($fsparam{'fs_host'},
         sprintf('%d', $fsparam{'fs_port'}),
         $fsparam{'fs_password'});
    
    $esl->connected() or die("Cannot connect to FreeSWITCH");
    $self->esl($esl);
    return;
}

sub DESTROY
{
    my $self = shift;
    
    if($self->esl->connected())
    {
        $self->esl->disconnect();
    }
}

sub dial
{
    my $self = shift;
    my $arg = shift;

    my $t = $self->tester;
    
    my $ret = {};
    
    my $esl = $self->esl;
    my $cfg = $t->cfg;

    my $bridge_string = $cfg->{'bridge_string'};
    my $substmacro = '${destination_number}';
    my $idx = index($bridge_string, $substmacro);
    my $dest = $arg->{'outbound_dest'};
    
    if( $idx >= 0 )
    {
        if( not defined($dest) )
        {
            die('Profile bridge_string specifies ${destination_number}, ' .
                'but dial() was called without dest argument');
        }
        
        substr($bridge_string, $idx, length($substmacro), $dest);
    }

    my $outbound_uuid = $esl->api('create_uuid')->getBody();
    $log->debug('Created UUID: ' . $outbound_uuid);
    $ret->{'uuid'} = $outbound_uuid;
    
    my $originate_string =
        'originate {ignore_early_media=true,origination_uuid=' .
            $outbound_uuid;
    
    $originate_string .= ',originate_timeout=60';

    if( defined($arg->{'outbound_callerid'}))
    {
        my $cid = $arg->{'outbound_callerid'};
        $originate_string .=
            sprintf(',origination_caller_id_number=%s,' .
                    'origination_caller_id_name=%s',
                    $cid, $cid);
    }
    else
    {
        $log->warn('outbound_callerid is not defined');
    }

    $originate_string .= ',jitterbuffer_msec=60:200';
    
    if( defined($cfg->{'setvars'}) )
    {
        foreach my $pair (@{$cfg->{'setvars'}})
        {
            $originate_string .=
                sprintf(',%s=%s', $pair->{'name'}, $pair->{'value'});
        }
    }

    if( defined($arg->{'outbound_codec'}) )
    {
        my $str = $arg->{'outbound_codec'};
        $str =~ s/,/\\,/g;
        $originate_string .=
            sprintf(',absolute_codec_string=%s', $str);
    }

    if( defined($arg->{'outbound_send_dtmf'}) )
    {
        if( ref($arg->{'outbound_send_dtmf'}) ne 'ARRAY' )
        {
            die('outbound_send_dtmf should be an array');
        }        
        
        my $type = $arg->{'outbound_send_dtmf_type'};
        if( not defined($type) )
        {
            $log->debug('Setting DTMF type to rfc2833');
            $type = 'rfc2833';
        }
        elsif( $type eq 'rfc2833' or $type eq 'info' )
        {
            $log->debug('Setting DTMF type to ' . $type);
        }
        else
        {
            $log->error('Invalid DTMF type: ' . $type . '. Setting to rfc2833');
            $type = 'rfc2833';
        }
        
        $originate_string .= sprintf(',dtmf_type=%s', $type);
    }
            
                
    if( $arg->{'outbound_record_audio'} )
    {
        my $dir = $cfg->{'record_dir'};
        $dir = '/var/tmp' unless defined($dir);

        my $wav = $dir . '/' . $outbound_uuid . '.wav';
        $ret->{'record'} = $wav;

        $originate_string .=
            ',RECORD_STEREO=true,execute_on_answer=\'record_session ' .
                $wav . '\'';
    }
        
    $originate_string .= '}' . $bridge_string;

    if( defined($arg->{'outbound_play'}) )
    {
        my $src = $arg->{'outbound_play'};
        
        if( $src eq 'moh' )
        {
            $originate_string .= ' &playback(local_stream://moh)';
        }
        elsif( -f $src )
        {
            $originate_string .= ' &playback(' . $src . ')';
        }
        else
        {
            die('Cannot find playback file: ' . $src);
        }
    }
    else
    {
        $originate_string .= ' &park()';
    }

    $t->trace->start($outbound_uuid);
    $ret->{'trace_file'} = $t->trace->trace_file();

    $esl->events('plain', 'CHANNEL_CREATE');
    $esl->events('plain', 'CHANNEL_ANSWER');
    $esl->events('plain', 'CHANNEL_DESTROY');
    $esl->events('plain', 'DTMF');

    $ret->{'originate_string'} = $originate_string;
    $log->debug('Originating call: ' . $originate_string);
    $esl->api($originate_string);

    if( $arg->{'outbound_hangup_after'} )
    {
        $log->debugf('Scheduling hangup after %d seconds',
                     $arg->{'outbound_hangup_after'});
        $esl->bgapi(sprintf('sched_hangup +%d %s',
                            $arg->{'outbound_hangup_after'}, $outbound_uuid));
    }

    if( defined($arg->{'outbound_send_dtmf'}) )
    {
        my ($delay, $str) = @{$arg->{'outbound_send_dtmf'}};
        $log->debugf('Scheduling DTMF string after ' .
                     $delay . ' seconds: ' . $str);
        $esl->bgapi
            (sprintf
             ('sched_api +%d none uuid_send_dtmf %s %s',
              $delay, $outbound_uuid, $str));
    }

    my $outbound_callid = '';
    my $outbound_originate_ts = 0;
    my $outbound_answer_ts = 0;
    my $outbound_duration = 0;
    my $outbound_dtmf = [];
    my $inbound_uuid = '';
    my $inbound_callid = '';
    my $inbound_dtmf = [];
    my $inbound_invite_ts = 0;
    my $inbound_answer_ts = 0;
    my $inbound_duration = 0;
    
    my $outbound_ongoing = 1;
    my $inbound_ongoing = 0;
    
    while($outbound_ongoing or $inbound_ongoing)
    {
        my $event = $esl->recvEventTimed(200);
        if( defined($event) )
        {
            my $type = $event->getType();
            my $event_uuid = $event->getHeader('Unique-ID');
            my $ts = $event->getHeader('Event-Date-Timestamp') / 1e6;
            
            if( $type eq 'CHANNEL_CREATE' )
            {
                if( defined($arg->{'inbound_match'}) and
                    $inbound_uuid eq '' and
                    $event->getHeader('Call-Direction') eq 'inbound' )
                {
                    my $match = 1;
                    foreach my $hdr (keys %{$arg->{'inbound_match'}})
                    {
                        if( $event->getHeader($hdr) !~
                            $arg->{'inbound_match'}{$hdr} )
                        {
                            $match = 0;
                            last;
                        }
                    }

                    if( $match )
                    {
                        $log->debugf('Matched an inbound call');
                        $inbound_uuid = $event_uuid;
                        $inbound_callid =
                            $event->getHeader('variable_sip_call_id');
                        $inbound_invite_ts = $ts;
                        $inbound_ongoing = 1;
                    }
                }
                elsif( $event_uuid eq $outbound_uuid )
                {
                    $outbound_originate_ts = $ts;
                }
            }
            elsif( $type eq 'CHANNEL_ANSWER' )
            {
                if( $event_uuid eq $outbound_uuid )
                {
                    $log->debugf('Outbound call answered');
                    $outbound_callid =
                        $event->getHeader('variable_sip_call_id');
                    $outbound_answer_ts = $ts;
                }
                elsif( $event_uuid eq $inbound_uuid )
                {
                    $inbound_answer_ts = $ts;
                }
            }
            elsif( $type eq 'CHANNEL_DESTROY' )
            {
                if( $event_uuid eq $outbound_uuid )
                {
                    $outbound_ongoing = 0;
                    $log->debugf('Outbound call stopped');
                    $outbound_duration =
                        $event->getHeader('variable_uduration') / 1e6;
                }
                elsif( $event_uuid eq $inbound_uuid )
                {
                    $inbound_ongoing = 0;
                    $log->debugf('Inbound call stopped');
                    $inbound_duration =
                        $event->getHeader('variable_uduration') / 1e6;
                }
            }
            elsif( $type eq 'DTMF' )
            {
                my $digit = {};
                foreach my $hdr ('DTMF-Digit', 'DTMF-Duration', 'DTMF-Source')
                {
                    $digit->{$hdr} = $event->getHeader($hdr);
                }
                
                $digit->{'ts'} = $ts;

                if( $event_uuid eq $inbound_uuid )
                {
                    push(@{$inbound_dtmf}, $digit);
                    $log->debugf('DTMF in inbound call: ' .
                                 $digit->{'DTMF-Digit'});
                }
                elsif( $event_uuid eq $outbound_uuid )
                {
                    push(@{$outbound_dtmf}, $digit);
                    $log->debugf('DTMF in outbound call: ' .
                                 $digit->{'DTMF-Digit'});
                }
            }
        }
    }

    $t->trace->stop();

    # by default, analyze outbound call only
    my $analyze_outbound = 1;
    my $analyze_inbound = 0;
    {
        my $val = $arg->{'analyze_sip'};
        if( defined($val) )
        {
            if( $val eq 'inbound' )
            {
                $analyze_outbound = 0;
                $analyze_inbound = 1;
            }
            elsif( $val eq 'both' )
            {
                $analyze_inbound = 1;
            }
            elsif( $val eq 'outbound' )
            {
                die('Unknown value of analyze_sip: ' . $val);
            }
        }
    }
                
    if( $analyze_outbound )
    {
        $t->trace->call_id($outbound_callid);
        my ($props, $errors) = $t->trace->analyze_call();

        $ret->{'outbound_callid'} = $outbound_callid;
        $ret->{'outbound_call_props'} = $props;
        $ret->{'outbound_call_errors'} = $errors;
        $ret->{'outbound_originate_ts'} = $outbound_originate_ts;
        $ret->{'outbound_answer_ts'} = $outbound_answer_ts;
        $ret->{'outbound_duration'} = $outbound_duration;
    }

    if( $analyze_inbound )
    {
        if( $inbound_callid eq '' )
        {
            die('Cannot determine inbound call ID');
        }

        $t->trace->call_id($inbound_callid);
        my ($props, $errors) = $t->trace->analyze_call();

        $ret->{'inbound_callid'} = $inbound_callid;
        $ret->{'inbound_dtmf'} = $inbound_dtmf;
        $ret->{'inbound_call_props'} = $props;
        $ret->{'inbound_call_errors'} = $errors;
        $ret->{'inbound_invite_ts'} = $inbound_invite_ts;
        $ret->{'inbound_answer_ts'} = $inbound_answer_ts;
        $ret->{'inbound_duration'} = $inbound_duration;
    }

    return $ret;
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
