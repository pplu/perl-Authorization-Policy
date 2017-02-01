package Authorization::Statement;

use Moose;

use Authorization::Types;

has sid           => (isa => 'Str|Undef', 
                      is => 'ro');
has effect        => (isa => 'Authorization::Statement::Effect', 
                      is => 'ro', required => 1, coerce => 1);
has principal     => (isa => 'Authorization::Principal', 
                      is => 'ro', coerce => 1);
has actions       => (isa => 'Autorization::Statement::ArrayRefOfAction', 
                      is => 'ro', required => 1, coerce => 1);
#has not_actions   => (isa => 'Autorization::Statement::ArrayRefOfAction', 
#                      is => 'ro', required => 1, coerce => 1);
has resources     => (isa => 'Autorization::Statement::ArrayRefOfResource', 
                      is => 'ro', required => 1, coerce => 1);
#has not_resources => (isa => 'Autorization::Statement::ArrayRefOfResource', 
#                      is => 'ro', required => 1, coerce => 1);
has conditions    => (isa => 'ArrayRef[Authorization::Statement::Condition]', 
                      is => 'ro');

sub from_hashref {
  my ($class, $h) = @_;
  
  return $class->new(sid => $h->{Sid},
                     effect => $h->{Effect},
                     principals => $h->{Principal},
                     #not_principals => $h->{NotPrincipal},
                     resources => $h->{Resource},
                     #not_resources => $h->{NotResource},
                     actions => $h->{Action},
                     #not_actions => $h->{NotAction},
                     );
}

sub evaluate {
  my ($self, $context) = @_;

  return undef unless (grep { $_->matches($context->resource) } @{ $self->resources });
  return undef unless (grep { $_->matches($context->action) } @{ $self->actions });
  die "Cannot evaluate principals yet" if (defined $self->principal);
  die "Cannot evaluate conditions yet" if (defined $self->conditions);

  #TODO: evaluate not_resources
  #TODO: evaluate not_actions

  return $self->effect;
}

1;
