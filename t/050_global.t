#!/usr/bin/env perl

use Authorization::Policy::Policy;
use Authorization::Policy::Context;
use Test::More;

my $policy = <<EOF;
{
    "Statement": [
        {
            "Action": ["service1:GetOperation"],
            "Effect": "Allow",
            "Resource": ["arn:aws:s3:::mybucket"],
            "Condition": {
                "StringLike": {
                    "s3:prefix": ["\${aws:username}/*"]
                }
            }
        },
        {
            "Action": [
                "service1:GetThings",
                "service2:PutThings"
            ],
            "Effect": "Allow",
            "Resource": ["arn:aws:s3:::*"]
        }
    ]
}
EOF

use JSON::MaybeXS;

my $hr = decode_json($policy);

my $stat = Authorization::Policy::Policy->from_hashref($hr);

cmp_ok(@{$stat->statements}, '==', 2, 'Got 2 statements');

cmp_ok($stat->evaluate(Authorization::Policy::Context->new(
    action => 'serivce1:GetThingy',
    resource => 'xxx:service:subservice::path/*',
    principal => { Principal => { 'XXX' => 'user' } }
  )),
  '==', 0, "Access to GetThingy denied");

cmp_ok($stat->evaluate(Authorization::Policy::Context->new(
    action => 'service1:GetThings',
    resource => 'arn:aws:s3:::path/to/thing',
    principal => { Principal => { 'XXX' => 'user' } }
  )),
  '==', 1, "Access to /path/to/thing Allowed");

done_testing;
