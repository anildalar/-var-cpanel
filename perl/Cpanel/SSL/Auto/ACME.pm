package Cpanel::SSL::Auto::ACME;

# cpanel - Cpanel/SSL/Auto/ACME.pm                Copyright(c) 2016 cPanel, Inc.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

#This will be common to any ACME-based AutoSSL providers.
##The filename will always be in the base64-URI “alphabet”.
use constant {
    REQUEST_URI_DCV_PATH           => '^/\\.well-known/acme-challenge/[0-9a-zA-Z_-]+$',
    URI_DCV_ALLOWED_CHARACTERS     => [ 0 .. 9, 'A' .. 'Z', '_', '-' ],
    URI_DCV_RANDOM_CHARACTER_COUNT => 32,
    URI_DCV_RELATIVE_PATH          => '.well-known/acme-challenge',
    EXTENSION                      => '',
};

1;
