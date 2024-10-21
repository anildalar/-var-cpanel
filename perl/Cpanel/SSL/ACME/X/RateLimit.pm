package Cpanel::SSL::ACME::X::RateLimit;

# cpanel - Cpanel/SSL/ACME/X/RateLimit.pm          Copyright 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ##  no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::ACME::X::RateLimit

=head1 DESCRIPTION

Instances of this exception class indicate that an ACME
request failed because a rate limit has been reached.

This class does not subclass L<Cpanel::Exception> because there is
never a need to stringify this error. It should B<always> be trapped
and handled gracefully.

=head1 METHODS

=head2 $obj = I<CLASS>->new( $ACME_ERROR )

Instantiates this class. $ACME_ERROR is a L<Net::ACME2::Error> instance
that describes the rate limit error.

=cut

sub new ( $class, $acme_error ) {    ## no critic qw(Proto)
    return bless [$acme_error], $class;
}

=head1 I<OBJ>->get_acme_error()

Returns the object’s stored L<Net::ACME2::Error> instance
that describes the rate limit error.

=cut

sub get_acme_error($self) {          ## no critic qw(Proto)
    return $self->[0];
}

1;
