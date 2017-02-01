package Authorization::Action;

use Moose;

has 'action' => (isa => 'Str', is => 'ro');

sub matches {
  my ($self, $accessing) = @_;

  my $re = $self->action;
  $re =~ s/\*/.*/g;
  $re = "^$re\$";

  return $accessing->action =~ m/$re/;
}

1;
