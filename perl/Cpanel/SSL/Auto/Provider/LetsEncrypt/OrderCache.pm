package Cpanel::SSL::Auto::Provider::LetsEncrypt::OrderCache;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/OrderCache.pm
#                                               Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::OrderCache

=head1 DESCRIPTION

Let’s Encrypt’s implementation of the IETF’s ACME standard (RFC 8555)
requires that a certificate order be created in order to do DCV.
That implementation also imposes a rate limit of 300 certificate orders
per 3-hour period. It is thus advantageous that the Let’s Encrypt provider
retain any certificate orders that were used for DCV and finalize those
rather than creating a new certificate order.

This class facilitates that by providing a simple set/get interface
for ACME certificate orders.

(NB: In testing, at least some “duplicate” certificate orders did I<not>
appear to count against the certificate orders rate limit—but we shouldn’t
depend on that, particularly since it’s easy to cache the orders.)

=cut

#----------------------------------------------------------------------

=head1 METHODS

=head2 $obj = I<CLASS>->new()

Instantiates this class.

=cut

sub new($class) {    ## no critic qw(Proto)
    return bless {}, $class;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->add( $ORDER )

Adds $ORDER (a L<Net::ACME2::Order> instance) to the cache.

Returns I<OBJ>.

=cut

sub add ( $self, $order ) {
    my @domains = map { $_->{'value'} } $order->identifiers();

    $self->{ _get_domains_lookup( \@domains ) } = $order;

    return $self;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->get( \@DOMAINS )

Retrieves a L<Net::ACME2::Order> instance previously created with C<set()>.
If no such instance is stored in I<OBJ>, undef is returned.

@DOMAINS is the set of domains that should be on the ACME order.
(NB: They need not be sorted in any particular way.)

=cut

sub get ( $self, $domains_ar ) {
    return $self->{ _get_domains_lookup($domains_ar) };
}

sub _get_domains_lookup ($domains_ar) {    ## no critic qw(Proto)

    # NB: sort() is a canonicalization method.
    return join( ',', sort @$domains_ar );
}

1;
