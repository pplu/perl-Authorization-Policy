#!/usr/bin/env perl

use strict;

use Test::More;

use Authorization::Policy::GroupPolicy;
use Authorization::Policy::Context;
use Authorization::Policy::Action;

my $policies = {
  empty_group_policy => Authorization::Policy::GroupPolicy->new(),
  can_do_everything_by_policy => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ),
  ),
  can_do_everything_by_group => Authorization::Policy::GroupPolicy->new(
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ) ],
  ),
  can_do_some_things_by_policy => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ 'GetSomething', 'PutX' ],
          effect => 'Allow'
        ),
      ]
    ),
  ),
  can_do_some_things_by_group => Authorization::Policy::GroupPolicy->new(
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ 'GetSomething', 'PutX' ],
          effect => 'Allow'
        ),
      ]
    ) ],
  ),
  negate_everything_by_group => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ),
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Deny'
        ),
      ]
    ) ],
  ),
  negate_some_ops_by_group => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ),
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ 'Get*', 'Put*' ],
          effect => 'Deny'
        ),
      ]
    ) ],
  ),
  negate_all_ops_by_user => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Deny'
        ),
      ]
    ),
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ) ],
  ),
  conflict_by_group_only => Authorization::Policy::GroupPolicy->new(
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Deny'
        ),
      ]
    ) ],
  ),
  conflict_by_group_only_reverse => Authorization::Policy::GroupPolicy->new(
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Deny'
        ),
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ) ],
  ),
  negate_everything_by_policy => Authorization::Policy::GroupPolicy->new(
    user_policy => Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Deny'
        ),
      ]
    ),
    group_policies => [ Authorization::Policy::Policy->new(
      statements => [
        Authorization::Policy::Statement->new(
          resources => 'x:x:x:x:x:x', 
          actions => [ '*' ],
          effect => 'Allow'
        ),
      ]
    ) ],
  ),

};

my $tests = [
  { access => 'GetSomething', match => 1, policy => 'can_do_everything_by_policy' },
  { access => 'PutX'        , match => 1, policy => 'can_do_everything_by_policy' },
  { access => 'ExecuteX'    , match => 1, policy => 'can_do_everything_by_policy' },

  { access => 'GetSomething', match => 1, policy => 'can_do_some_things_by_policy' },
  { access => 'PutX'        , match => 1, policy => 'can_do_some_things_by_policy' },
  { access => 'ExecuteX'    , match => 0, policy => 'can_do_some_things_by_policy' },

  { access => 'GetSomething', match => 0, policy => 'empty_group_policy' },
  { access => 'PutX'        , match => 0, policy => 'empty_group_policy' },
  { access => 'ExecuteX'    , match => 0, policy => 'empty_group_policy' },

  { access => 'GetSomething', match => 1, policy => 'can_do_everything_by_group' },
  { access => 'PutX'        , match => 1, policy => 'can_do_everything_by_group' },
  { access => 'ExecuteX'    , match => 1, policy => 'can_do_everything_by_group' },

  { access => 'GetSomething', match => 0, policy => 'negate_all_ops_by_user' },
  { access => 'PutX'        , match => 0, policy => 'negate_all_ops_by_user' },
  { access => 'ExecuteX'    , match => 0, policy => 'negate_all_ops_by_user' },

  { access => 'GetSomething', match => 1, policy => 'can_do_some_things_by_group' },
  { access => 'PutX'        , match => 1, policy => 'can_do_some_things_by_group' },
  { access => 'ExecuteX'    , match => 0, policy => 'can_do_some_things_by_group' },

  { access => 'GetSomething', match => 0, policy => 'negate_everything_by_group' },
  { access => 'PutX'        , match => 0, policy => 'negate_everything_by_group' },
  { access => 'ExecuteX'    , match => 0, policy => 'negate_everything_by_group' },

  { access => 'GetSomething', match => 0, policy => 'negate_everything_by_policy' },
  { access => 'PutX'        , match => 0, policy => 'negate_everything_by_policy' },
  { access => 'ExecuteX'    , match => 0, policy => 'negate_everything_by_policy' },

  { access => 'GetSomething', match => 0, policy => 'negate_some_ops_by_group' },
  { access => 'PutX'        , match => 0, policy => 'negate_some_ops_by_group' },
  { access => 'ExecuteX'    , match => 1, policy => 'negate_some_ops_by_group' },

  { access => 'GetSomething', match => 0, policy => 'conflict_by_group_only' },
  { access => 'PutX'        , match => 0, policy => 'conflict_by_group_only' },
  { access => 'ExecuteX'    , match => 0, policy => 'conflict_by_group_only' },

  { access => 'GetSomething', match => 0, policy => 'conflict_by_group_only_reverse' },
  { access => 'PutX'        , match => 0, policy => 'conflict_by_group_only_reverse' },
  { access => 'ExecuteX'    , match => 0, policy => 'conflict_by_group_only_reverse' },
];

foreach my $test (@$tests) {
  my $access = Authorization::Policy::Context->new(
    action => $test->{ access }, 
    resource => 'x:x:x:x:x:x', 
    principal => { Principal => { AWS => 'x:x:x:x:x:x' } }, 
  );
  my $policy = $policies->{ $test->{ policy } };
  die "No polict for $test->{ policy }" if (not defined $policy);

  if ($test->{ match }){
    ok($policy->evaluate($access), "Try to $test->{ access } with policy $test->{ policy }" );
  } else {
    isnt($policy->evaluate($access), 1, "Try to $test->{ access } with policy $test->{ policy }");
  }
}

done_testing;

1;
