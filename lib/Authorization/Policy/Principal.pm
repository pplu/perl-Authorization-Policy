package Authorization::Policy::Principal;

use Moose;

use Authorization::Policy::Types;

has namespace => (isa => 'Str', 
                  is => 'ro', required => 1);

has accounts  => (isa => 'Authorization::Policy::Principal::ArrayRefOfStr', 
#has accounts  => (isa => 'ArrayRef[Str]',
                  coerce => 1, 
                  is => 'ro', required => 1);

sub from_hashref {
  my ($class, $hashref) = @_;

  my $ppal = $hashref->{Principal};
  die "Expecting 'Principal' key in Principal" if (not defined $ppal);

  my %temp = %$ppal;
  my ($namespace, $accounts) = (each %temp);

  return $class->new(namespace => $namespace, accounts => $accounts); 
}

sub matches {
  my ($self, $accessing) = @_;

  return 0 if ($self->namespace ne $accessing->principal->namespace);
  return 1 if (grep { $accessing->principal->accounts->[0] eq $_ } @{ $self->accounts });
  return 0;
}

1;
