#!/usr/bin/env perl

use Test::More;

use Authorization::Policy::Principal;
use Authorization::Policy::Context;
use Authorization::Policy::Policy;

use strict;

my $tests = [
  { principal => { Principal => { SVC => 'x:x:x:x:x:x' } }, 
    access    => { Principal => { SVC => 'x:x:x:x:x:x' } },
    match     => 1
  },
  { principal => { Principal => { SVC => ['x:x:x:x:x:x', 'y:y:y:y:y:y' ] } }, 
    access    => { Principal => { SVC => 'x:x:x:x:x:x' } },
    match     => 1
  },
  { principal => { Principal => { SVC => ['y:y:y:y:y:y', 'x:x:x:x:x:x' ] } }, 
    access    => { Principal => { SVC => 'x:x:x:x:x:x' } },
    match     => 1
  },
  { principal => { Principal => { SVC => 'x:x:x:x:x:y' } }, 
    access    => { Principal => { SVC => 'x:x:x:x:x:x' } },
    match     => 0
  },
  { principal => { Principal => { SVC => 'x:x:x:x:x:x' } }, 
    access    => { Principal => { SXX => 'x:x:x:x:x:x' } },
    match     => 0
  }, 
  { principal => { Principal => { SVC => ['y:y:y:y:y:y', 'z:z:z:z:z:z' ] } }, 
    access    => { Principal => { SVC => 'x:x:x:x:x:x' } },
    match     => 0
  },
];

foreach my $test (@$tests) {
  my $ctx = Authorization::Policy::Context->new( action => 'ActionX', 
                                         resource => 'x:x:x:x:x:x', 
                                         principal => $test->{access} );

  my $ppal = Authorization::Policy::Principal->from_hashref($test->{principal});

  my $s_ctx = to_str($ctx->principal);
  my $s_ppal = to_str($ppal);

  if ($test->{ match }){
    ok($ppal->matches($ctx), "Accessing $s_ctx against $s_ppal results in match");
  } else {
    isnt($ppal->matches($ctx), 1, "Accessing $s_ctx against $s_ppal results in no match");
  }
}

foreach my $test (@$tests) {
  my $stmt = Authorization::Policy::Policy->new( statements => [
                                                   Authorization::Policy::Statement->new(
                                                     resources => 'x:x:x:x:x:x', 
                                                     actions => 'ActionX', 
                                                     principal => $test->{ principal },
                                                     effect => 'Allow'
                                                   )
                                                 ]
                                               );
  my $ctx = Authorization::Policy::Context->new(
                                             action => 'ActionX',
                                             resource => 'x:x:x:x:x:x',
                                             principal => $test->{ access });
  my $s_ctx = to_str($ctx->principal);
  my $s_ppal = to_str($stmt->statements->[0]->principal);

  cmp_ok($stmt->evaluate($ctx),
         '==', 
         $test->{match}, 
         "Expect $test->{result} accessing $s_ctx with policy for $s_ppal"); 
}


{
  my $stmt = Authorization::Policy::Policy->new( statements => [
                                                   Authorization::Policy::Statement->new(
                                                     resources => 'x:x:x:x:x:x', 
                                                     actions => 'ActionX', 
                                                     effect => 'Allow'
                                                   )
                                                 ]
                                               );
  my $ctx = Authorization::Policy::Context->new(
                                             action => 'ActionX',
                                             resource => 'x:x:x:x:x:x',
                                             principal => { Principal => { 'SVC' => 'user' } });

  cmp_ok($stmt->evaluate($ctx),
         '==', 
         1, 
         "Pass a policy with no principal");
}






sub to_str {
  my $a = shift;
  return sprintf "{ Principal: '%s': [ '%s' ] }", $a->namespace, (join "','", @{ $a->accounts });
}

done_testing;
