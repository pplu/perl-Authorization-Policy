package Authorization::Policy::Context;

use Moose;

use Authorization::Policy::Types;

has resource => (isa => 'Authorization::Policy::Resource', is => 'ro', required => 1, coerce => 1);
has action => (isa => 'Authorization::Policy::Action', is => 'ro', required => 1, coerce => 1);
#has principal => (isa => 'Authorization::Policy::Principal', is => 'ro', required => 1, coerce => 1);

1;
