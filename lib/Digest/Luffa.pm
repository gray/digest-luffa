package Digest::Luffa;

use strict;
use warnings;
use parent qw(Exporter Digest::base);

use MIME::Base64 ();

our $VERSION = '0.03';
$VERSION = eval $VERSION;

eval {
    require XSLoader;
    XSLoader::load(__PACKAGE__, $VERSION);
    1;
} or do {
    require DynaLoader;
    DynaLoader::bootstrap(__PACKAGE__, $VERSION);
};

our @EXPORT_OK = qw(
    luffa_224 luffa_224_hex luffa_224_base64
    luffa_256 luffa_256_hex luffa_256_base64
    luffa_384 luffa_384_hex luffa_384_base64
    luffa_512 luffa_512_hex luffa_512_base64
);

# TODO: convert to C.
sub luffa_224_hex  { unpack 'H*', luffa_224(@_) }
sub luffa_256_hex  { unpack 'H*', luffa_256(@_) }
sub luffa_384_hex  { unpack 'H*', luffa_384(@_) }
sub luffa_512_hex  { unpack 'H*', luffa_512(@_) }

sub luffa_224_base64 {
    my $b64 = MIME::Base64::encode(luffa_224(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub luffa_256_base64 {
    my $b64 = MIME::Base64::encode(luffa_256(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub luffa_384_base64 {
    my $b64 = MIME::Base64::encode(luffa_384(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub luffa_512_base64 {
    my $b64 = MIME::Base64::encode(luffa_512(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}

sub add_bits {
    my ($self, $data, $bits) = @_;
    if (2 == @_) {
        return $self->_add_bits(pack('B*', $data), length $data);
    }
    return $self->_add_bits($data, $bits);
}


1;

__END__

=head1 NAME

Digest::Luffa - Perl interface to the Luffa digest algorithm

=head1 SYNOPSIS

    # Functional interface
    use Digest::Luffa qw(luffa_256 luffa_256_hex luffa_256_base64);

    $digest = luffa_256($data);
    $digest = luffa_256_hex($data);
    $digest = luffa_256_base64($data);

    # Object-oriented interface
    use Digest::Luffa;

    $ctx = Digest::Luffa->new(256);

    $ctx->add($data);
    $ctx->addfile(*FILE);

    $digest = $ctx->digest;
    $digest = $ctx->hexdigest;
    $digest = $ctx->b64digest;

=head1 DESCRIPTION

The C<Digest::Luffa> module provides an interface to the Luffa message
digest algorithm. Luffa is a candidate in the NIST SHA-3 competition.

This interface follows the conventions set forth by the C<Digest> module.

=head1 FUNCTIONS

The following functions are provided by the C<Digest::Luffa> module. None
of these functions are exported by default.

=head2 luffa_224($data, ...)

=head2 luffa_256($data, ...)

=head2 luffa_384($data, ...)

=head2 luffa_512($data, ...)

Logically joins the arguments into a single string, and returns its Luffa
digest encoded as a binary string.

=head2 luffa_224_hex($data, ...)

=head2 luffa_256_hex($data, ...)

=head2 luffa_384_hex($data, ...)

=head2 luffa_512_hex($data, ...)

Logically joins the arguments into a single string, and returns its Luffa
digest encoded as a hexadecimal string.

=head2 luffa_224_base64($data, ...)

=head2 luffa_256_base64($data, ...)

=head2 luffa_384_base64($data, ...)

=head2 luffa_512_base64($data, ...)

Logically joins the arguments into a single string, and returns its Luffa
digest encoded as a Base64 string, without any trailing padding.

=head1 METHODS

The object-oriented interface to C<Digest::Luffa> is identical to that
described by C<Digest>, except for the following:

=head2 new

    $luffa = Digest::Luffa->new(256)

The constructor requires the algorithm to be specified. It must be one of:
224, 256, 384, 512.

=head2 algorithm

=head2 hashsize

Returns the algorithm used by the object.

=head1 PERFORMANCE

This distribution contains a benchmarking script which compares the various
message digest algorithms available on CPAN. These are the results on
a MacBook 2GHz Core 2 Duo (64-bit) with Perl 5.12.2, using a message size of
1KB:

md5          245759/s  240 MB/s
skein_512    227104/s  222 MB/s
bmw_384      215039/s  210 MB/s
bmw_512      214369/s  209 MB/s
skein_256    194606/s  190 MB/s
blake_384    158510/s  155 MB/s
blake_512    150312/s  147 MB/s
bmw_224      131523/s  128 MB/s
bmw_256      131522/s  128 MB/s
blake_224    119301/s  117 MB/s
skein_1024   119300/s  117 MB/s
blake_256    119300/s  117 MB/s
sha1         115924/s  113 MB/s
shabal_224    96376/s   94 MB/s
shabal_512    95467/s   93 MB/s
shabal_256    95467/s   93 MB/s
shabal_384    94575/s   92 MB/s
sha_256       75918/s   74 MB/s
sha_512       75918/s   74 MB/s
sha_384       73080/s   71 MB/s
sha_224       73080/s   71 MB/s
keccak_224    60151/s   59 MB/s
keccak_256    60151/s   59 MB/s
luffa_224     54613/s   53 MB/s
luffa_256     54613/s   53 MB/s
keccak_384    49321/s   48 MB/s
shavite3_256  47287/s   46 MB/s
shavite3_224  47287/s   46 MB/s
fugue_256     46849/s   46 MB/s
fugue_224     46849/s   46 MB/s
md6_224       46419/s   45 MB/s
md6_256       43952/s   43 MB/s
luffa_384     40193/s   39 MB/s
echo_256      39097/s   38 MB/s
echo_224      38745/s   38 MB/s
md6_384       35544/s   35 MB/s
keccak_512    34133/s   33 MB/s
fugue_384     31508/s   31 MB/s
simd_256      30632/s   30 MB/s
simd_224      30351/s   30 MB/s
md6_512       30075/s   29 MB/s
shavite3_512  29805/s   29 MB/s
shavite3_384  29805/s   29 MB/s
luffa_512     29538/s   29 MB/s
cubehash_384  28183/s   28 MB/s
cubehash_256  28183/s   28 MB/s
cubehash_512  28109/s   27 MB/s
cubehash_224  28109/s   27 MB/s
hamsi_256     24889/s   24 MB/s
hamsi_224     24661/s   24 MB/s
whirlpool     24661/s   24 MB/s
fugue_512     23209/s   23 MB/s
echo_512      21154/s   21 MB/s
echo_384      20958/s   20 MB/s
simd_512      17454/s   17 MB/s
simd_384      17454/s   17 MB/s
jh_384        14354/s   14 MB/s
jh_512        14221/s   14 MB/s
jh_224        14221/s   14 MB/s
jh_256        14221/s   14 MB/s
hamsi_384      7587/s    7 MB/s
hamsi_512      7587/s    7 MB/s

=head1 SEE ALSO

L<Digest>

L<http://www.sdl.hitachi.co.jp/crypto/luffa/>

L<http://en.wikipedia.org/wiki/NIST_hash_function_competition>

L<http://www.saphir2.com/sphlib/>

=head1 REQUESTS AND BUGS

Please report any bugs or feature requests to
L<http://rt.cpan.org/Public/Bug/Report.html?Digest-Luffa>. I will be
notified, and then you'll automatically be notified of progress on your bug
as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Digest::Luffa

You can also look for information at:

=over

=item * GitHub Source Repository

L<http://github.com/gray/digest-luffa>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Digest-Luffa>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Digest-Luffa>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/Public/Dist/Display.html?Name=Digest-Luffa>

=item * Search CPAN

L<http://search.cpan.org/dist/Digest-Luffa/>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 gray <gray at cpan.org>, all rights reserved.

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 AUTHOR

gray, <gray at cpan.org>

=cut
