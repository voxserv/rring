
package Rring::Tester;

use Moose;
use YAML;
use Log::Any;

our $log = Log::Any->get_logger;

has 'profile' =>
    (
     is  => 'ro',
     isa => 'Str',
     required => 1,
    );


has 'cfg' =>
    (
     is  => 'rw',
     isa => 'HashRef',
     init_arg => undef,
    );

has 'caller' =>
    (
     is  => 'rw',
     isa => 'Object',
     init_arg => undef,
    );

has 'trace' =>
    (
     is  => 'rw',
     isa => 'Object',
     init_arg => undef,
    );


sub BUILD
{
    my $self = shift;
    
    my $cfg = YAML::LoadFile($self->profile);
    $self->cfg($cfg);

    foreach my $attr ('name')
    {
        if( not defined($cfg->{$attr}) )
        {
            die(sprintf('Missing "%s" in profile %s', $attr, $self->profile));
        }
    }

    
    foreach my $handle ('caller', 'trace')
    {
        my $attr = $handle . '_class';
        my $class = $cfg->{$attr};
        if( not defined($class) )
        {
            die(sprintf('Missing "%s" in profile %s', $attr, $self->profile));
        }
        
        eval('require ' . $class);
        if( $@ )
        {
            die(sprintf('Cannot load %s from profile %s: %s',
                        $attr, $self->profile, $@));
        }
        
        eval('$self->' . $handle . '(' .
             $class . '->new(\'tester\' => $self))');
        if( $@ )
        {
            die(sprintf('Cannot initialize %s: %s', $class, $@));
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
