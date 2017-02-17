package Authorization::Policy::Policy;

use Moose;

use Authorization::Policy::Statement;

has statements => (isa => 'ArrayRef[Authorization::Policy::Statement]', is => 'rw');
has message => (isa => 'Str', is => 'ro');

sub from_hashref {
  my ($class, $hashref) = @_;
  my $statements = [];

  push @$statements, Authorization::Policy::Statement->from_hashref($_) foreach (@{$hashref->{Statement}});
  return $class->new(statements => $statements);
}

sub evaluate {
  my ($self, $context) = @_;

  my $decision = undef;

  my $statements = $self->statements;
  my $i = 0;
  while ($i < @$statements) {
    my $ret = $statements->[$i]->evaluate($context);
    if (defined $ret) {
      return 0      if ($ret == 0);
      $decision = 1 if ($ret == 1);
    }
    $i++;
  }

  $decision = 0 if (not defined $decision);
  return $decision;
}

1;
