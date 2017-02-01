package Authorization::Context;

use Moose;

use Authorization::Types;

has resource => (isa => 'Authorization::Resource', is => 'ro', required => 1, coerce => 1);
has action => (isa => 'Authorization::Action', is => 'ro', required => 1, coerce => 1);
#has principal => (isa => 'Authorization::Principal', is => 'ro', required => 1, coerce => 1);

1;
