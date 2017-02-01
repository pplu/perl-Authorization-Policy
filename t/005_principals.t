#!/usr/bin/env perl

use Test::More;

use Authorization::Principal;
use Authorization::Context;
use Authorization::Policy;

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
  my $ctx = Authorization::Context->new( action => 'ActionX', 
                                         resource => 'a:a:a:a:a:a', 
                                         principal => $test->{access} );

  my $ppal = Authorization::Principal->from_hashref($test->{principal});

  my $s_ctx = to_str($ctx->principal);
  my $s_ppal = to_str($ppal);

  if ($test->{ match }){
    ok($ppal->matches($ctx), "Accessing $s_ctx against $s_ppal results in match");
  } else {
    isnt($ppal->matches($ctx), 1, "Accessing $s_ctx against $s_ppal results in no match");
  }

  my $stmt = Authorization::Policy->new( statements => resources => 'x:x:x:x:x:x', 
                                             actions => $test->{ action }, 
                                             principal => { Principal => { AWS => 'x:x:x:x:x:x' } },
                                             effect => 'Allow'
                                            );


}

sub to_str {
  my $a = shift;
  return sprintf "{ Principal: '%s': [ '%s' ] }", $a->namespace, (join "','", @{ $a->accounts });
}

done_testing;
