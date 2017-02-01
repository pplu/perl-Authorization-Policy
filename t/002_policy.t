#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Authorization::Policy;
use Authorization::Statement;
use Authorization::Context;

my $res = [ 'xxx:service:subservice:::' ];
my $act = [ 'MyAction' ];
 
my $context = Authorization::Context->new(
  principal => { Principal => { AWS => 'x:x:x:x:x:x' } }, 
  resource => $res->[0],
  action => $act->[0]  
);

my $deny = Authorization::Statement->new(
  sid => 'DENY',
  effect => 'Deny',
  resources => $res,
  actions => $act
);

my $allow = Authorization::Statement->new(
  sid => 'ALLOW',
  effect => 'Allow',
  resources => $res,
  actions => $act
);

my $na = Authorization::Statement->new(
  sid => 'NA',
  effect => 'Allow',
  resources => [ 'yyy:service::subservice:::' ],
  actions => [ 'NotMyAction' ],
);

my $tests = [
  { result => 'Deny',  statements => [ ] },
  { result => 'Deny',  statements => [ $na ] },
  { result => 'Deny',  statements => [ $na, $deny ] },
  { result => 'Allow', statements => [ $na, $allow ] },
  { result => 'Deny',  statements => [ $deny ] },
  { result => 'Deny',  statements => [ $deny, $na ] },
  { result => 'Deny',  statements => [ $deny, $allow ] },
  { result => 'Allow', statements => [ $allow ] },
  { result => 'Allow', statements => [ $allow, $na ] },
  { result => 'Deny',  statements => [ $allow, $deny ] },
  { result => 'Deny',  statements => [ $deny, $allow, $deny ] },
  { result => 'Deny',  statements => [ $na  , $allow, $deny ] },
  { result => 'Deny',  statements => [ $deny, $deny, $allow ] },
  { result => 'Deny',  statements => [ $deny, $na  , $allow ] },
  { result => 'Deny',  statements => [ $allow, $deny, $deny ] },
  { result => 'Deny',  statements => [ $allow, $deny, $na   ] },
  { result => 'Deny',  statements => [ $na, $na, $na ] },
  { result => 'Deny',  statements => [ $allow, $allow, $allow, $deny ] },
  { result => 'Deny',  statements => [ $deny, $allow, $allow, $allow ] },
  { result => 'Deny',  statements => [ $allow, $allow, $deny, $allow ] },
];

foreach my $test (@$tests){
  my $statement = Authorization::Policy->new( statements => $test->{statements} );
  cmp_ok($statement->evaluate($context), 
         '==', 
         ($test->{result} eq 'Allow' ? 1 : 0), 
         "Expect $test->{result} from " . join ',', map { $_->sid } @{ $test->{statements} });
}

done_testing;
