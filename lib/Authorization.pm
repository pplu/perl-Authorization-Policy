package Authorization;

use Moose;
use Moose::Util::TypeConstraints;

coerce 'Authorization::Resource',
  from 'Str',
  via { Authorization::Resource->from_string( $_ ) };

coerce 'Authorization::Action',
  from 'Str',
  via { Authorization::Action->new( action => $_ ) };

subtype 'Authorization::Statement::Effect',
  as 'Int',
  where { $_ == 0 or $_ == 1 },
  message { "effect can only be 0, 1, Allow, Deny. Unexpected $_" };

coerce 'Authorization::Statement::Effect',
  from 'Str',
  via { { Deny => 0, Allow => 1 }->{ $_ } };

subtype 'Autorization::Statement::ArrayRefOfResource',
  as 'ArrayRef[Authorization::Resource]';

subtype 'Autorization::Statement::ArrayRefOfStr',
  as 'ArrayRef[Str]';

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Autorization::Statement::ArrayRefOfStr',
  via { [ map { Authorization::Resource->from_string( $_ ); } @$_ ] };
 
coerce 'Autorization::Statement::ArrayRefOfResource', 
  from 'Str', 
  via { [ Authorization::Resource->from_string( $_ ) ] };

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Authorization::Resource',
  via { [ $_ ] };

subtype 'Authorization::Principal::ArrayRefOfStr',
  as 'ArrayRef[Str]';

coerce 'Authorization::Principal::ArrayRefOfStr',
  from 'Str',
  via { return [ $_ ] };

coerce 'Authorization::Principal',
  from 'HashRef',
  via { Authorization::Principal->from_hashref( $_ ) };


# -------- Action coercion ----------------------------

subtype 'Autorization::Statement::ArrayRefOfAction',
  as 'ArrayRef[Authorization::Action]';

coerce 'Autorization::Statement::ArrayRefOfAction',
  from 'Autorization::Statement::ArrayRefOfStr', 
  via { [ map { Authorization::Action->new( action => $_ ); } @$_ ] };

coerce 'Autorization::Statement::ArrayRefOfAction', 
  from 'Str', 
  via { [ Authorization::Action->new( action => $_ ) ] };

coerce 'Autorization::Statement::ArrayRefOfResource',
  from 'Authorization::Action',
  via { [ $_ ] };

use Authorization::Context;
use Authorization::Resource;
use Authorization::Principal;

1;
