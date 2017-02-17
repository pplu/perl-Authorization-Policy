#!/usr/bin/env perl

use Authorization::Policy::Context;
use Authorization::Policy::Policy;
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

use JSON;

my $hr = from_json($policy);

my $stat = Authorization::Policy::Policy->from_hashref($hr);

cmp_ok(@{$stat->statements}, '==', 2, 'Got 2 statements');

use Data::Dumper;
print Dumper($stat);

my $eval = $stat->evaluate(Authorization::Policy::Context->new(
  action => 'GetThingy',
  resource => 'xxx:service:subservice::path/*'
));

ok($eval, "Access to GetThingy denied");

done_testing;
