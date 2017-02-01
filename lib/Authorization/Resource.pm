package Authorization::Resource;

use Moose;

has 'organization' => (isa => 'Str', is => 'rw', required => 1 );
has 'namespace' => (isa => 'Str', is => 'rw', required => 1 );
has 'service' => (isa => 'Str', is => 'rw', required => 1 );
has 'location' => (isa => 'Str', is => 'rw', default => '*' );
has 'account' => (isa => 'Str', is => 'rw', default => '*' );
has 'resource' => (isa => 'Str', is => 'rw', default => '' );

sub from_string {
  my ($class, $string) = @_;

  $string = '*:*:*:*:*:*' if ($string eq '*');

  my ($org, $ns, $svc, $loc, $acc, $res) = split /:/, $string, 6;
  $res = '*' if (not defined $res);
  $acc = '*' if (not defined $acc);
  $loc = '*' if (not defined $loc);

  return $class->new( 
               organization => $org,
               namespace => $ns,
               service   => $svc,
               location  => $loc,
               account   => $acc,
               resource  => $res,
  );
}

sub matches {
  my ($self, $accessing) = @_;

  my $re = $self->resource || '*';
  $re =~ s/\*/.*/g;
  $re = "^$re\$";
 
  my $acc = $self->account || '*';
  my $loc = $self->location || '*';

  return ( (($self->organization ne '*') ? $self->organization eq $accessing->organization : 1 ) and
           (($self->namespace    ne '*') ? $self->namespace    eq $accessing->namespace    : 1 ) and
           (($self->service      ne '*') ? $self->service      eq $accessing->service      : 1 ) and
           (($loc                ne '*') ? $loc                eq $accessing->location     : 1 ) and
           (($acc                ne '*') ? $acc                eq $accessing->account      : 1 ) and
           ($accessing->resource =~ m/$re/)
         );
}

1;
