package Authorization::Policy::Types;

use Moose;
use Moose::Util::TypeConstraints;

use Authorization::Policy::Action;
use Authorization::Policy::Resource;
use Authorization::Policy::Principal;

coerce 'Authorization::Policy::Principal',
  from 'HashRef',
  via { Authorization::Policy::Principal->from_hashref( $_ ) };

coerce 'Authorization::Policy::Resource',
  from 'Str',
  via { Authorization::Policy::Resource->from_string( $_ ) };

coerce 'Authorization::Policy::Action',
  from 'Str',
  via { Authorization::Policy::Action->new( action => $_ ) };


subtype 'Authorization::Policy::Principal::ArrayRefOfStr',
  as 'ArrayRef[Str]';

coerce 'Authorization::Policy::Principal::ArrayRefOfStr',
  from 'Str',
  via { [ $_ ] };

subtype 'Authorization::Policy::Statement::Effect',
  as 'Int',
  where { $_ == 0 or $_ == 1 },
  message { "effect can only be 0, 1, Allow, Deny. Unexpected $_" };

coerce 'Authorization::Policy::Statement::Effect',
  from 'Str',
  via { { Deny => 0, Allow => 1 }->{ $_ } };

subtype 'Autorization::Statement::ArrayRefOfResource',
  as 'ArrayRef[Authorization::Policy::Resource]';

subtype 'Autorization::Statement::ArrayRefOfStr',
  as 'ArrayRef[Str]';

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Autorization::Statement::ArrayRefOfStr',
  via { [ map { Authorization::Policy::Resource->from_string( $_ ); } @$_ ] };
 
coerce 'Autorization::Statement::ArrayRefOfResource', 
  from 'Str', 
  via { [ Authorization::Policy::Resource->from_string( $_ ) ] };

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Authorization::Policy::Resource',
  via { [ $_ ] };

# -------- Action coercion ----------------------------

subtype 'Autorization::Statement::ArrayRefOfAction',
  as 'ArrayRef[Authorization::Policy::Action]';

coerce 'Autorization::Statement::ArrayRefOfAction',
  from 'Autorization::Statement::ArrayRefOfStr', 
  via { [ map { Authorization::Policy::Action->new( action => $_ ); } @$_ ] };

coerce 'Autorization::Statement::ArrayRefOfAction', 
  from 'Str', 
  via { [ Authorization::Policy::Action->new( action => $_ ) ] };

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Authorization::Policy::Action',
  via { [ $_ ] };

1;
