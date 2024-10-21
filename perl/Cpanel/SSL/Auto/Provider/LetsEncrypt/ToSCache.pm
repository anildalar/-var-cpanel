package Cpanel::SSL::Auto::Provider::LetsEncrypt::ToSCache;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/ToSCache.pm
#                                                  Copyright 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::ToSCache

=head1 SYNOPSIS

    my $tos_url = Cpanel::SSL::Auto::Provider::LetsEncrypt::ToSCache::get($acme);

=head1 DESCRIPTION

This module implements a cache of Let’s Encrypt’s terms of service URL.

=head1 BACKGROUND

The L<ACME protocol|https://tools.ietf.org/html/rfc8555> includes a
mechanism for an ACME server to specify terms of service (“ToS”) via a URL.
Historically, L<Let’s Encrypt|http://letsencrypt.org>’s ACME server
has had periods of downtime during which WHM was unable to fetch that
ToS URL. This resulted in a hung WHM “Manage AutoSSL” UI.

The originally-deployed ACME protocol server included an “unofficial”
static redirect, L<https://acme-v01.api.letsencrypt.org/terms>, that
we realized could be used in lieu of fetching the ToS from the ACME server.
This obviated any need to obtain a potentially-changing ToS, which
was a big win for the “Manage AutoSSL” UI.

Let’s Encrypt has opted, however, not to deploy a similar static redirect
for their v2 endpoint, which again necessitates hitting the ACME server
to fetch a ToS URL. To prevent Let’s Encrypt downtimes from killing
the “Manage AutoSSL” UI, then, this module implements a cache of the ACME
server’s reported ToS URL.

=cut

#----------------------------------------------------------------------

use Cpanel::Alarm     ();
use Cpanel::Debug     ();
use Cpanel::Exception ();
use Cpanel::Try       ();

our $_TIMEOUT = 30;

our $_CACHE_PATH = '/root/.cpanel/letsencrypt_tos_cache';

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $url = get( $ACME_OBJ )

$ACME_OBJ is a L<Net::ACME2> instance. This makes a best-effort at
returning a Terms of Service URL. It first attempts to fetch the
URL from the ACME server; if that succeeds, then the cache is written,
but if it fails, then we fall back to reading the cache.

Note that the cache is only consulted I<after> an attempt to read from
the authoritative source has failed. This simplifies the workflow by
forgoing a need for cache expiration logic. (We can always modify this
later if needs dictate.)

=cut

sub get($acme) {    ## no critic qw(Proto)
    my $url;

    my $ref = ref $acme;

    Cpanel::Try::try(
        sub {
            $url = do {
                local $SIG{'ALRM'} = sub {
                    die Cpanel::Exception::create_raw( 'Timeout', q<> );
                };

                my $alarm = Cpanel::Alarm->new($_TIMEOUT);

                $acme->get_terms_of_service();
            };

            warn if !eval {
                require File::Slurper::Temp;
                File::Slurper::Temp::write_text( $_CACHE_PATH, $url );
                1;
            };
        },
        'Cpanel::Exception::Timeout' => sub {
            Cpanel::Debug::log_warn("${ref}->get_terms_of_service(): Timed out! Reading terms of service cache …\n");
        },
        q<> => sub {
            Cpanel::Debug::log_warn("${ref}->get_terms_of_service(): $@\nReading terms of service cache …\n");
        },
    );

    return $url ||= do {
        require File::Slurper;

        File::Slurper::read_text($_CACHE_PATH) =~ s<\s*><>gr;
    };
}

1;
