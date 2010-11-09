use strict;
use warnings;
use Test::More tests => 11;
use Digest::Luffa;

new_ok('Digest::Luffa' => [$_], "algorithm $_") for qw(224 256 384 512);

is(eval { Digest::Luffa->new },     undef, 'no algorithm specified');
is(eval { Digest::Luffa->new(10) }, undef, 'invalid algorithm specified');

can_ok('Digest::Luffa',
    qw(clone algorithm hashsize add digest hexdigest b64digest)
);

for my $alg (qw(224 256 384 512)) {
    my $d1 = Digest::Luffa->new($alg);
    is(
        $d1->add('foobar')->hexdigest, $d1->clone->hexdigest,
        "clone of $alg"
    );
}
