#!/usr/bin/env perl

use strict;

use Test::More;

use Authorization::Policy::Policy;
use Authorization::Policy::Context;
use Authorization::Policy::Action;

my $ts = [
  { access => 'GetSomething', action => 'GetSomething', match => 1 },
  { access => 'GetSomething', action => 'Get*', match => 1 },
  { access => 'GetSomething', action => 'PutSomething', match => 0 },
  { access => 'GetSomething', action => 'Put*', match => 0 },
  { access => 'GetSomething', action => '*', match => 1 },
];

foreach my $test (@$ts){
  my $action = Authorization::Policy::Action->new(action => $test->{ action });
  my $access  = Authorization::Policy::Action->new(action => $test->{ access });
  if ($test->{ match }){
    ok($action->matches($access), "Accessing $test->{ access } against $test->{ action } results in match");
  } else {
    isnt($action->matches($access), 1, "Accessing $test->{ access } against $test->{ action } results in no match");
  }
}

my $tests = [
  { access => 'GetSomething', action => 'GetSomething', match => 1 },
  { access => 'PutX'        , action => 'PutX'        , match => 1 },
  { access => 'GetSomething', action => 'Get*', match => 1 },
  { access => 'GetSomething', action => 'Put*', match => 0 },
  { access => 'GetSomething', action => 'PutSomething', match => 0 },
  { access => 'GetSomething', action => 'Put*', match => 0 },
  { access => 'PutX'        , action => 'Put*', match => 1 },
  { access => 'GetSomething', action => '*', match => 1 },
  { access => 'PutSomething', action => '*', match => 1 },
  { access => 'GetSomething', action => [ 'Put*', 'GetSomething' ], match => 1 },
  { access => 'GetSomething', action => [ 'GetSomething', 'Put*' ], match => 1 },
  { access => 'GetSomething', action => [ 'GetAnother', 'Put*' ], match => 0 },
  { access => 'GetSomething', action => [ 'Get*', 'Put*' ], match => 1 },
  { access => 'GetSomething', action => [ 'Put*', 'Get*' ], match => 1 },
  { access => 'GetSomething', action => [ '*' ], match => 1 },
];

foreach my $test (@$tests) {
  my $access = Authorization::Policy::Context->new(action => $test->{ access }, 
                                           resource => 'x:x:x:x:x:x', 
                                           principal => { Principal => { AWS => 'x:x:x:x:x:x' } }, 
                                          );
  my $action = Authorization::Policy::Policy->new(
                                           statements => [
                                             Authorization::Policy::Statement->new(
                                               resources => 'x:x:x:x:x:x', 
                                               actions => $test->{ action }, 
                                               effect => 'Allow'
                                             )
                                           ]
                                         );
  my $str;
  if (ref($test->{action}) eq 'ARRAY'){
    $str = join ',', @{ $test->{ action } };
  } else {
    $str = $test->{ action };
  }

  if ($test->{ match }){
    ok($action->evaluate($access), "Method $test->{ access } accessing $str" );
  } else {
    isnt($action->evaluate($access), 1, "Method $test->{ access } accessing $str");    
  }
}

done_testing;

1;
