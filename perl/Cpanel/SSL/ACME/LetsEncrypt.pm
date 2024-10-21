package Cpanel::SSL::ACME::LetsEncrypt;

# cpanel - Cpanel/SSL/ACME/LetsEncrypt.pm       Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::ACME::LetsEncrypt - Convenience logic for Let’s Encrypt

=head1 SYNOPSIS

    if ( Cpanel::SSL::ACME::LetsEncrypt::error_is_orders_rate_limit($acme_err) ) {
        # However we want to handle this specific error type …
    }

=head1 FUNCTIONS

=head2 $yn = error_is_orders_rate_limit($ACME_ERR)

Accepts a L<Net::ACME2::Error> instance and returns a boolean that
indicates whether that object represents Let’s Encrypt’s rate limit
on certificate orders. (As of this writing, that limit defaults to
300 orders per 3-hour period.)

=cut

sub error_is_orders_rate_limit($acme_err) {    ## no critic qw(Proto)
    return 0 if $acme_err->type() ne 'urn:ietf:params:acme:error:rateLimited';

    # As of July 2019 Let’s Encrypt provides no mechanism more
    # reliable than this to distinguish one rate limit from another.
    # cf. https://community.letsencrypt.org/t/programmatically-distinguishing-rate-limits/97986/5
    return $acme_err->detail() =~ m<too many new orders> ? 1 : 0;
}

1;
