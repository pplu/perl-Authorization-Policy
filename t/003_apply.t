#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use Authorization::Policy::Policy;
use Authorization::Policy::Context;
use Authorization::Policy::Resource;

my $tests = [
  { accessing => 'xxx:service:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 1 },
  { accessing => 'xxx:service:subservice:location:user1:xxx/yyy', 
    resource => 'xxx:service:subservice:location:user1:xxx/*'   , result => 1 },
  { accessing => 'xxx:service:subservice:location:user1:xxx/yyy', 
    resource => 'xxx:service:subservice:location:user1:*'       , result => 1 },
  { accessing => 'xxx:sssssss:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:::xxx/*'               , result => 1 },
  { accessing => 'xxx:service:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:::*'                   , result => 1 },
  { accessing => 'yyy:service:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:sssssss:subservice:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:ssssssssss:location:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:subservice:llllllll:user1:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:subservice:location:uuuuu:xxx/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:subservice:location:user1:aaa/yyy', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:subservice:location:user1:xxx/bbb', 
    resource  => 'xxx:service:subservice:location:user1:xxx/yyy', result => 0 },
  { accessing => 'xxx:service:ssssssssss:location:user1:xxx/yyy', 
    resource  => '*'                                            , result => 1 },
];

foreach my $test (@$tests){
  my $ctx = Authorization::Policy::Context->new(
    principal => { Principal => { AWS => 'x:x:x:x:x:x' } }, 
    resource => $test->{ accessing }, 
    action => 'GetX' );
  my $res = Authorization::Policy::Resource->from_string( $test->{resource} );
  
  cmp_ok($res->matches($ctx->resource), 
         '==', 
         $test->{result}, 
         "Expect $test->{result} accessing $test->{ accessing } with resource string $test->{ resource }");

  my $stmt = Authorization::Policy::Policy->new( 
    statements => [ 
      Authorization::Policy::Statement->new(
        principal => { Principal => { AWS => 'x:x:x:x:x:x' } }, 
        resources => $test->{resource},
        actions   => 'GetX',
        effect    => 'Allow'
      )
    ]
  );

  cmp_ok($stmt->evaluate($ctx),
         '==', 
         $test->{result}, 
         "Expect $test->{result} accessing $test->{ accessing } with policy for $test->{ resource }");
}

done_testing;
