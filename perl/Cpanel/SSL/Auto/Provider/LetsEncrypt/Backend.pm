package Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/Backend.pm
#                                               Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use experimental qw(signatures);

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend

=cut

#----------------------------------------------------------------------

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $epoch_or_undef = get_epoch_seconds_if_is_acceptable_expiry_time( $RFCDATE )

$RFCDATE is a date string as L<DateTime::Format::RFC3339> can parse it.

If that date is sufficiently far into the future, this function returns
$RFCDATE in epoch seconds. Otherwise, undef is returned.

=cut

sub get_epoch_seconds_if_is_acceptable_expiry_time($expiry) {
    local ( $!, $@ );

    require DateTime;
    require DateTime::Format::RFC3339;

    $expiry = DateTime::Format::RFC3339->new()->parse_datetime($expiry);

    my $padded_expiry = $expiry->clone()->subtract( hours => 1 );
    my $now           = _now();

    if ( -1 == DateTime->compare( $now, $padded_expiry ) ) {
        return $expiry->epoch();
    }

    return undef;
}

sub _now {
    require DateTime;
    return DateTime->now();
}

#----------------------------------------------------------------------

=head2 @failed = do_http_dcv( $ACME_DCV, $AUTOSSL_DCV, \@DOMAINS, $STATE_OBJ_OR_UNDEF )

Runs Let’s Encrypt’s HTTP DCV and returns a list of the failed domains
(or, in scalar context, the number of such that would be returned in list
context).

Arguments are:

=over

=item * C<$ACME_DCV> - a L<Cpanel::SSL::ACME::DCV> instance

=item * C<$AUTOSSL_DCV> - a L<Cpanel::SSL::Auto::ProviderDCV> instance

=item * C<\@DOMAINS> - reference to an array of domains to check

=item * C<$STATE_OBJ_OR_UNDEF> - if defined, a L<Cpanel::SSL::Auto::Provider::LetsEncrypt::SavedState> instance

=back

=cut

sub do_http_dcv ( $acme_dcv, $autossl_dcv, $domains_ar, $state_obj ) {    ## no critic qw(Proto)

    my ( $callback, $failures_ar ) = _get_dcv_callback_cr( $acme_dcv, $autossl_dcv, 'http' );

    my $username = $autossl_dcv->get_username();

    $acme_dcv->attempt_http( $username, $callback, @$domains_ar );

    if ($state_obj) {
        _save_state( $state_obj, $acme_dcv, $autossl_dcv, $domains_ar, 'http' );
    }

    return @$failures_ar;
}

#----------------------------------------------------------------------

=head2 @failed = do_dns_dcv( $ACME_DCV, $AUTOSSL_DCV, \@DOMAINS, $STATE_OBJ_OR_UNDEF )

Like C<do_http_dcv()> but for DNS DCV.

=cut

sub do_dns_dcv ( $acme_dcv, $autossl_dcv, $domains_ar, $state_obj ) {    ## no critic qw(Proto)

    my ( $callback, $failures_ar ) = _get_dcv_callback_cr( $acme_dcv, $autossl_dcv, 'dns' );

    $acme_dcv->attempt_dns( $callback, @$domains_ar );

    if ($state_obj) {
        _save_state( $state_obj, $acme_dcv, $autossl_dcv, $domains_ar, 'dns' );
    }

    return @$failures_ar;
}

=head2 ( $http_ar, $dns_ar ) = split_domains_by_dcv_method( $PROVIDER_OBJ, \@DOMAINS, $AUTOSSL_DCV )

Splits @DOMAINS into two arrays: one for HTTP DCV, and the other for DNS DCV.

$PROVIDER_OBJ is a L<Cpanel::SSL::Auto::Provider> subclass instance.
$AUTOSSL_DCV is a L<Cpanel::SSL::Auto::ProviderDCV> instance.

=cut

sub split_domains_by_dcv_method ( $provider_obj, $domains_ar, $autossl_dcv ) {    ## no critic qw(Proto)

    my ( @http_domains, @dns_domains );

    for my $d (@$domains_ar) {

        my $method = $autossl_dcv->get_dcv_method_or_die($d);

        # Let’s Encrypt requires DNS DCV for wildcards.
        if ( $method eq 'http' && 0 == rindex( $d, '*.', 0 ) ) {
            local ( $@, $! );
            require Cpanel::Locale;

            $provider_obj->log( info => Cpanel::Locale->get_handle()->maketext( 'Per “[_1]” policy, switching to [asis,DNS] [asis,DCV] for “[_2]” …', $provider_obj->DISPLAY_NAME(), $d ) );
            $method = 'dns';
        }

        if ( 'http' eq $method ) {
            push @http_domains, $d;
        }
        elsif ( 'dns' eq $method ) {
            push @dns_domains, $d;
        }

        # Sanity check for programmer errors:
        else {
            die "Bad DCV method ($d): “$method”";
        }
    }

    return ( \@http_domains, \@dns_domains );
}

#----------------------------------------------------------------------

use constant _STATE_REPORT_ERR => {
    http => 'set_http_error',
    dns  => 'set_dns_error',
};

use constant _AUTOSSL_REPORT_ERR => {
    http => 'add_http_warning',
    dns  => 'add_dns_failure',
};

use constant _AUTOSSL_REPORT_OK => {
    http => 'add_http_success',
    dns  => 'add_dns_success',
};

sub _save_state ( $state_obj, $acme_dcv, $autossl_dcv, $domains_ar, $dcv_type ) {
    local $@;

    for my $domain (@$domains_ar) {
        if ( $autossl_dcv->get_domain_success_method($domain) ) {
            my $expiry = $acme_dcv->get_authz_expiry($domain);

            warn if !eval { $state_obj->set_success_expiry( $domain, $expiry ); };
        }
        else {
            my $failures_ar = $autossl_dcv->get_domain_failures($domain);

            my $fn = _STATE_REPORT_ERR()->{$dcv_type};

            warn if !eval { $state_obj->$fn( $domain, $failures_ar->[-1] ) };
        }
    }

    return;
}

sub _get_dcv_callback_cr ( $acme_dcv, $autossl_dcv, $dcv_type ) {
    my @failed;

    my $callback = sub ( $domain, $reason, $override_dcv_type = undef ) {
        my $real_dcv_type = $override_dcv_type || $dcv_type;

        if ($reason) {
            push @failed, $domain;

            my $fn = _AUTOSSL_REPORT_ERR()->{$real_dcv_type};
            $autossl_dcv->$fn( $domain, $reason );
        }
        else {
            my $fn = _AUTOSSL_REPORT_OK()->{$real_dcv_type};
            $autossl_dcv->$fn($domain);
        }
    };

    return ( $callback, \@failed );
}

1;
