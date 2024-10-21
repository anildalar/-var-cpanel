package Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/Constants.pm
#                                                  Copyright 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants

=head1 DESCRIPTION

This module contains various constants that the
main LE provider module inherits but that are useful in other modules
where we don’t want to load the full LE provider module.

=cut

use constant {
    DAYS_TO_REPLACE => 29,

    #cf. https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769
    MAX_DOMAINS_PER_CERTIFICATE => 100,

    DISPLAY_NAME => 'Let’s Encrypt™',

    #https://community.letsencrypt.org/t/how-many-http-redirects-does-le-allow-for-challenges/19113
    HTTP_DCV_MAX_REDIRECTS => 10,

    USE_LOCAL_DNS_DCV => 1,

    CAA_STRING => 'letsencrypt.org',

    SUPPORTS_WILDCARD => 1,
};

=head1 NONSTANDARD CONSTANTS

=head2 SOFT_MAX_DOMAINS_PER_CERTIFICATE()

Keep the size of the certificate down if we can …
it’ll load faster that way.

=cut

# (This has to be a full sub {}, not a constant, because the test
# expects to be able to override this value.)
sub SOFT_MAX_DOMAINS_PER_CERTIFICATE { return 24; }

1;
