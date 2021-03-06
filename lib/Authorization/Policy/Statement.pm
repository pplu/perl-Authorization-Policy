package Authorization::Policy::Statement;

use Moose;

use Authorization::Policy::Action;
use Authorization::Policy::Resource;
use Authorization::Policy::Principal;

use Authorization::Policy::Types;

has sid           => (isa => 'Str|Undef', 
                      is => 'ro');
has effect        => (isa => 'Authorization::Policy::Statement::Effect', 
                      is => 'ro', required => 1, coerce => 1);
has principal     => (isa => 'Authorization::Policy::Principal', 
                      is => 'ro', coerce => 1);
has actions       => (isa => 'Autorization::Statement::ArrayRefOfAction', 
                      is => 'ro', required => 1, coerce => 1);
#has not_actions   => (isa => 'Autorization::Statement::ArrayRefOfAction', 
#                      is => 'ro', required => 1, coerce => 1);
has resources     => (isa => 'Autorization::Statement::ArrayRefOfResource', 
                      is => 'ro', required => 1, coerce => 1);
#has not_resources => (isa => 'Autorization::Statement::ArrayRefOfResource', 
#                      is => 'ro', required => 1, coerce => 1);
has conditions    => (isa => 'ArrayRef[Authorization::Policy::Statement::Condition]', 
                      is => 'ro');

sub from_hashref {
  my ($class, $h) = @_;
  
  return $class->new(sid => $h->{Sid},
                     effect => $h->{Effect},
                     (defined $h->{Principal})?(principal => $h->{Principal}):(),
                     #not_principals => $h->{NotPrincipal},
                     resources => $h->{Resource},
                     #not_resources => $h->{NotResource},
                     actions => $h->{Action},
                     #not_actions => $h->{NotAction},
                     );
}

sub evaluate {
  my ($self, $context) = @_;

  return undef if (defined $self->principal and not $self->principal->matches($context));
  return undef unless (grep { $_->matches($context->resource) } @{ $self->resources });
  return undef unless (grep { $_->matches($context->action) } @{ $self->actions });
  #return undef unless (defined $self->principal and $self->principal->matches($context));
  die "Cannot evaluate conditions yet" if (defined $self->conditions);

  #TODO: evaluate not_resources
  #TODO: evaluate not_actions

  return $self->effect;
}

1;
