
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
    my $dest = $arg->{'dest'};
    
    if( $idx >= 0 )
    {
        if( not defined($dest) )
        {
            die('Profile bridge_string specifies ${destination_number}, ' .
                'but dial() was called without dest argument');
        }
        
        substr($bridge_string, $idx, length($substmacro), $dest);
    }

    my $uuid = $esl->api('create_uuid')->getBody();
    $log->debug('Created UUID: ' . $uuid);
    $ret->{'uuid'} = $uuid;
    
    my $originate_string =
        'originate {ignore_early_media=true,origination_uuid=' . $uuid;
    
    $originate_string .= ',originate_timeout=60';

    if( defined($arg->{'callerid'}))
    {
        my $cid = $arg->{'callerid'};
        $originate_string .=
            sprintf(',origination_caller_id_number=%s,' .
                    'origination_caller_id_name=%s',
                    $cid, $cid);
    }
    else
    {
        $log->warn('callerid is not defined');
    }

    $originate_string .= ',jitterbuffer=60:200:20';
    
    if( defined($cfg->{'setvars'}) )
    {
        foreach my $pair (@{$cfg->{'setvars'}})
        {
            $originate_string .=
                sprintf(',%s=%s', $pair->{'name'}, $pair->{'value'});
        }
    }

    if( defined($arg->{'codec'}) )
    {
        my $str = $arg->{'codec'};
        $str =~ s/,/\\,/g;
        $originate_string .=
            sprintf(',absolute_codec_string=%s', $str);
    }

    if( defined($arg->{'send_dtmf'}) )
    {
        if( ref($arg->{'send_dtmf'}) ne 'ARRAY' )
        {
            die('send_dtmf should be an array');
        }        
        
        my $type = $arg->{'dtmf_type'};
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
            
                
    if( $arg->{'record_audio'} )
    {
        my $dir = $cfg->{'record_dir'};
        $dir = '/var/tmp' unless defined($dir);

        my $wav = $dir . '/' . $uuid . '.wav';
        $ret->{'record'} = $wav;

        $originate_string .=
            ',RECORD_STEREO=true,execute_on_answer=\'record_session ' .
                $wav . '\'';
    }
        
    $originate_string .= '}' . $bridge_string;

    if( defined($arg->{'play'}) )
    {
        my $src = $arg->{'play'};
        
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

    $t->trace->start($uuid);
    $ret->{'trace_file'} = $t->trace->trace_file();
        
    $ret->{'originate_string'} = $originate_string;
    $log->debug('Originating call: ' . $originate_string);
    $esl->api($originate_string);

    if( $arg->{'hangup_after'} )
    {
        $log->debugf('Scheduling hangup after %d seconds',
                     $arg->{'hangup_after'});
        $esl->bgapi(sprintf('sched_hangup +%d %s',
                            $arg->{'hangup_after'}, $uuid));
    }

    if( defined($arg->{'send_dtmf'}) )
    {
        my ($delay, $str) = @{$arg->{'send_dtmf'}};
        $log->debugf('Scheduling DTMF string after ' .
                     $delay . ' seconds: ' . $str);
        $esl->bgapi
            (sprintf
             ('sched_api +%d none uuid_send_dtmf %s %s',
              $delay, $uuid, $str));
    }

    my $callid = '';
    my $go_on = 1;
    while($go_on)
    {
        usleep(250);
        my $val = $esl->api('uuid_exists ' . $uuid)->getBody();
        if( $val ne 'true' )
        {
            $go_on = 0;
            $log->debugf('Call stopped');
        }
        else
        {
            if( $callid eq '' or $callid eq '_undef_' )
            {
                $callid = $esl->api('uuid_getvar ' . $uuid .
                                    ' sip_call_id')->getBody();
            }
        }
    }

    $t->trace->stop();
    
    if( $callid eq '' or $callid eq '_undef_' )
    {
        die('The call has not properly started');
    }
    
    $log->debug('SIP Call id: ' . $callid);
    $t->trace->out_call_id($callid);
    $t->trace->analyze_outbound_call();

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
