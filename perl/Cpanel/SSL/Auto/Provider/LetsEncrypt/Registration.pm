package Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/Registration.pm
#                                               Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;
use autodie;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration

=head1 DESCRIPTION

This module manages a single server-wide Let’s Encrypt registration.

=cut

#----------------------------------------------------------------------

use Try::Tiny;

use JSON          ();
use File::Slurper ();

use constant _ENVIRONMENT => 'production';    # alternatively: “staging”

our $CACHE_PATH = '/var/cpanel/letsencrypt-v2.json';

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $le_obj = get_acme($KEY_ID)

Creates a new L<Net::ACME2::LetsEncrypt> instance, reusing any saved
key and key ID.

=cut

sub get_acme {
    my ( $key_pem, $key_id );

    # IMPORTANT: These two properties (“private_key_pem” and “uri”)
    # should remain as they are in order to preserve easy compatibility
    # with registration files from the v1 API’s AutoSSL plugin.

    if ( my $reg_hr = _get_cache() ) {
        ( $key_pem, $key_id ) = @{$reg_hr}{ 'private_key_pem', 'uri' };
    }
    else {
        $key_pem = _create_account_key();
        _set_cache( { private_key_pem => $key_pem } );
    }

    require Net::ACME2::LetsEncrypt;
    return Net::ACME2::LetsEncrypt->new(
        key         => $key_pem,
        key_id      => $key_id,
        environment => _ENVIRONMENT(),
    );
}

=head2 save_key_id($KEY_ID)

Updates an existing registration cache with a key ID.
If no registration cache exists, this throws an exception.

=cut

sub save_key_id($key_id) {    ## no critic qw(Proto)
    my $cache = _get_cache() or die "LE registration cache is missing!";

    $cache->{'uri'} = $key_id or die 'No key ID given!';

    _set_cache($cache);

    return;
}

#----------------------------------------------------------------------

=head2 $yn = forget()

Deletes any existing registration. Returns 1 if something was
deleted and 0 if no registration existed in the first place.

=cut

sub forget {
    local $!;
    return 1 if CORE::unlink($CACHE_PATH);

    if ( !$!{'ENOENT'} ) {
        die "unlink($CACHE_PATH): $!";
    }

    return 0;
}

#----------------------------------------------------------------------

sub _create_account_key {
    local ( $!, $@ );
    require Net::SSLeay;

    # Use ECC for account keys since it’s faster/safer than RSA.
    my $pk = Net::SSLeay::EVP_PKEY_new();
    my $gen = Net::SSLeay::EC_KEY_generate_key('secp384r1') or Net::SSLeay::die_now('failed to generate secp384r1 key!');
    Net::SSLeay::EVP_PKEY_assign_EC_KEY( $pk, $gen );

    return Net::SSLeay::PEM_get_string_PrivateKey($pk);
}

#----------------------------------------------------------------------
# NB: These functions aren’t race-safe. We could use Cpanel::SafeFile,
# but it’s better to minimize dependencies on the mainline cPanel code
# base, and race safety seems unlikely to be a problem with this datastore
# since it’ll generally be written once and not updated thereafter.

sub _get_cache {
    my $json;

    try {
        $json = File::Slurper::read_text($CACHE_PATH);
    }
    catch {
        my $err = $_;

        require Errno;

        my $enoent = do { local $! = Errno::ENOENT(); "$!" };

        if ( $err !~ m<$enoent> ) {
            local $@ = $_;
            die;
        }
    };

    return defined($json) ? JSON::decode_json($json) : undef;
}

sub _set_cache($cache_hr) {    ## no critic qw(Proto)

    # We don’t use File::Slurper::Temp here because we want to
    # chmod() the file before the rename().

    require File::Temp;
    my ( undef, $temp ) = File::Temp::tempfile( "$CACHE_PATH.tmp.XXXXXX", CLEANUP => 1 );

    File::Slurper::write_text( $temp, JSON::encode_json($cache_hr) );

    chmod 0600, $temp;

    rename $temp => $CACHE_PATH;

    return;
}

1;
