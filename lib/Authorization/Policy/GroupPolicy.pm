package Authorization::Policy::GroupPolicy;

use Moose;
use Authorization::Policy::Policy;

has group_policies => (
  isa => 'ArrayRef[Authorization::Policy::Policy]', 
  is => 'ro',
  default => sub { [] }
);

has user_policy => (
  isa => 'Authorization::Policy::Policy',
  is => 'ro'
);

sub statements {
  my $self = shift;
  my $statements = [];

  foreach my $group (@{ $self->group_policies }) {
    push @$statements, @{ $group->statements };
  }
  push @$statements, $self->user_policy if (defined $self->user_policy);
  return $statements;
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
