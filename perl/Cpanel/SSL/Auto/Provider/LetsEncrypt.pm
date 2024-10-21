package Cpanel::SSL::Auto::Provider::LetsEncrypt;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt.pm
#                                               Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

=pod

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt - AutoSSL provider for Let’s Encrypt

=head1 DESCRIPTION

An cPanel AutoSSL provider for Let’s Encrypt

=cut

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

use parent qw(
  Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants
  Cpanel::SSL::Auto::ACME
  Cpanel::SSL::Auto::Provider
);

use Cpanel::SSL::ACME                                            ();
use Cpanel::SSL::ACME::LetsEncrypt                               ();
use Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend            ();
use Cpanel::SSL::Auto::Provider::LetsEncrypt::OrderCache         ();
use Cpanel::SSL::Auto::Provider::LetsEncrypt::SingleDomainBucket ();
use Cpanel::SSL::Auto::Wildcard                                  ();

use Try::Tiny;

use Crypt::Format ();

use Cpanel::Exception          ();
use Cpanel::Try                ();
use Cpanel::LoadModule::Custom ();

#https://community.letsencrypt.org/t/best-way-to-determine-a-certificate-comes-from-let-s-encrypt/16133
my $LETS_ENCRYPT_ISSUER_REGEX = q<(?:Let(?:'|’)?s Encrypt)>;

use constant CHECK_FREQUENCY => '3hours';

use Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration ();

sub _get_acme($self) {    ## no critic qw(Proto)

    # This allows several methods in this module to be called
    # as class methods or as instance methods.
    $self = {} if !ref $self;

    return $self->{'_acme'} ||= Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration::get_acme();
}

sub _create_rsa_key {
    require Crypt::OpenSSL::RSA;
    return Crypt::OpenSSL::RSA->generate_key(2048)->get_private_key_string();
}

sub PROPERTIES($self) {    ## no critic qw(Proto)

    my $acme = $self->_get_acme();

    Cpanel::LoadModule::Custom::load_perl_module('Cpanel::SSL::Auto::Provider::LetsEncrypt::ToSCache');

    my $terms = Cpanel::SSL::Auto::Provider::LetsEncrypt::ToSCache::get($acme);

    return (
        account_id                => $acme->key_id(),
        terms_of_service          => $terms,
        terms_of_service_accepted => $acme->key_id() ? 1 : 0,
    );
}

sub EXPORT_PROPERTIES ( $self, %props ) {    ## no critic qw(Proto)

    delete $props{'terms_of_service_accepted'} or do {
        die "Must submit “terms_of_service_accepted”!";
    };

    if ( my @keys = sort keys %props ) {
        die "Unrecognized properties: @keys";
    }

    my $acme = $self->_get_acme();

    if ( !$acme->key_id() ) {

        # This updates the return of $acme->key_id().
        $acme->create_account( termsOfServiceAgreed => 1 );

        Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration::save_key_id( $acme->key_id() );
    }

    return;
}

*RESET = *Cpanel::SSL::Auto::Provider::LetsEncrypt::Registration::forget;

sub CERTIFICATE_PARSE_IS_FROM_HERE ( $self, $parse ) {    ## no critic qw(Proto)

    for my $i_ar ( @{ $parse->{'issuer_list'} } ) {
        return 1 if $i_ar->[1] =~ m<$LETS_ENCRYPT_ISSUER_REGEX>o;
    }

    return 0;
}

sub CERTIFICATE_IS_FROM_HERE ( $self, $cert_pem ) {       ## no critic qw(Proto)

    #Prefer the CPAN module for this rather than cPanel’s
    #internal tools since CPAN offers a more stable API.
    require Crypt::OpenSSL::X509;

    my $x509 = Crypt::OpenSSL::X509->new_from_string(
        $cert_pem,
        Crypt::OpenSSL::X509::FORMAT_PEM(),
    );

    return $x509->issuer() =~ m<$LETS_ENCRYPT_ISSUER_REGEX>o;
}

=head2 I<OBJ>->renew_ssl( .. )

See L<Cpanel::SSL::Auto::Provider> for docs for this interface.

=cut

sub renew_ssl ( $self, %opts ) {    ## no critic qw(Proto)

    my ( $username, $vh_domains_hr ) = @opts{ 'username', 'vhost_domains' };

    my %domain_to_vhost = map {
        my $vhost_name = $_;
        map { $_ => $vhost_name } @{ $vh_domains_hr->{$vhost_name} }
    } keys %$vh_domains_hr;

    my $acme = $self->_get_acme();

    my %pruned_vhost_to_domains;

    %pruned_vhost_to_domains = %$vh_domains_hr;

    Cpanel::LoadModule::Custom::load_perl_module('Cpanel::SSL::Auto::Provider::LetsEncrypt::RegisteredDomains') if !$INC{'Cpanel/SSL/Auto/Provider/LetsEncrypt/RegisteredDomains.pm'};

    my $cert_buckets = Cpanel::SSL::Auto::Provider::LetsEncrypt::RegisteredDomains::get_certificate_buckets_grouped_by_registered_domain( $username, { domain_to_vhost => \%domain_to_vhost, vhost_to_domains => \%pruned_vhost_to_domains } );

    if ( my $singles_ar = $opts{'single_domains'} ) {
        push @$cert_buckets, map { Cpanel::SSL::Auto::Provider::LetsEncrypt::SingleDomainBucket->new($_); } @$singles_ar;
    }

    my $locale = _locale();

  BUCKET:
    for my $bkt_idx ( 0 .. $#$cert_buckets ) {
        my $cert_bucket = $cert_buckets->[$bkt_idx];

        my @bkt_domains = @{ $cert_bucket->domains() };

        my $domains_desc;

        $self->_log_about_cert_and_domains( $bkt_idx, \@bkt_domains );

        my $order = $self->_get_cached_order( \@bkt_domains );

        if ($order) {
            $self->log( 'info', $locale->maketext('Reusing certificate order from [output,abbr,DCV,Domain Control Validation] …') );
        }
        else {
            $self->log( 'info', $locale->maketext('Creating certificate order …') );

            # This stopgap prevents, e.g., “foo.bar.com” and
            # “*.bar.com” on the same certificate (which LE forbids).
            #  It may be ideal to do this in RegisteredDomains.pm, but
            # eventually we hope to have AutoSSL itself handle the wildcard
            # reductions (TODO), which should obviate this logic anyway.
            _remove_wildcard_redundancies( \@bkt_domains );

            $order = $self->_create_order_for_domains(@bkt_domains);

            next BUCKET if !$order;
        }

        my $key_pem;

        # generate_key() was added to Provider.pm in v92.
        if ( $self->can('generate_key') ) {
            $key_pem = $self->generate_key($username);
        }
        else {
            $key_pem = _create_rsa_key();
        }

        # We forgo sorting @bkt_domains because LE ignores the order of
        # domains in the CSR and applies its own sort order anyway.
        #
        # https://community.letsencrypt.org/t/san-sort-order/116616
        #
        my $csr_pem = _create_csr( $key_pem, @bkt_domains );

        $self->_finalize_order_and_confirm( $order, $csr_pem );

        my $chain_txt = $acme->get_certificate_chain($order);

        my ( $cert_pem, @cab ) = Crypt::Format::split_pem_chain($chain_txt);

        for my $setname ( @{ $cert_bucket->domain_set_names() } ) {

            # v92 and later:
            if ( $self->can('handle_new_certificate') ) {

                # On 30 Sep 2021 the “DST Root CA X3” root certificate expired.
                # This was the cert that allowed Let’s Encrypt certs to be
                # valid initially, before they had their own root.
                #
                # As of 1 Oct 2021 that root certificate is still what their
                # API’s returned cert chain points to. This is intentional in
                # order to preserve compatibility with old Android devices,
                # which disregard trust anchor expiry during verification.
                # (This is apparently a legitimate design, however unusual it
                # may be.)
                #
                # The problem with that for us, though, is that CentOS 7’s
                # default OpenSSL (1.0.2) considers those chains to be
                # invalid unless OpenSSL is configured in “trusted-first”
                # mode. So if “trusted-first” mode is on we can use the
                # more-compatible chain that Let’s Encrypt provides. If we
                # *can’t* confirm that “trusted-first” mode is on, then we
                # give just the leaf certificate to the installer, which will
                # cause the installer to grab the CA bundle from the
                # the certificates’ CA Issuers URLs. That version of the CA
                # bundle needs a newer trusted root, which sacrifices
                # compatibility with some older Android devices but is at
                # least valid in CentOS 7’s OpenSSL’s default configuration.
                #
                my $cab_pem = $self->can('SSL_VERIFY_USES_TRUSTED_FIRST') ? join( "\n", @cab ) : undef;

                $self->handle_new_certificate(
                    username        => $username,
                    domain_set_name => $setname,

                    certificate_pem => $cert_pem,
                    key_pem         => $key_pem,
                    cab_pem         => $cab_pem,
                );
            }

            # pre-v92:
            else {
                try {
                    $self->install_certificate(
                        certificate_pem => $cert_pem,
                        key_pem         => $key_pem,

                        web_vhost_name => $setname,
                    );

                    $self->log( 'success', _locale()->maketext( 'The system has installed a new certificate onto “[_1]”’s website “[_2]”.', $username, $setname ) );
                }
                catch {
                    $self->log( 'warn', "Certificate installation error: $_" );
                };
            }
        }
    }

    # We assume that this function will be called once per user,
    # so it’s safe to clear the provider’s ACME order object cache.
    undef $self->{'_cached_order'};

    return;
}

sub _remove_wildcard_redundancies( $domains_ar ) {
    my @wildcards = grep { 0 == rindex( $_, '*.', 0 ) } @$domains_ar;
    for my $wc_domain (@wildcards) {
        Cpanel::SSL::Auto::Wildcard::substitute_wildcard_for_domains( $wc_domain, $domains_ar );
    }

    return;
}

# i.e., when it’s time to actually procure and install a certificate
sub _log_about_cert_and_domains ( $self, $bkt_idx, $domains_ar ) {
    my $domains_desc;

    my ($shortest_domain) = sort { length $a <=> length $b } @$domains_ar;

    if ( @$domains_ar > 2 ) {
        $domains_desc = _locale()->maketext( '“[_1]” and [quant,_2,other domain,other domains]', $shortest_domain, @$domains_ar - 1 );
    }
    elsif ( @$domains_ar == 2 ) {
        $domains_desc = _locale()->list_and_quoted($domains_ar);
    }
    else {
        $domains_desc = _locale()->maketext( '“[_1]” only', $shortest_domain );
    }

    $self->log( 'info', _locale()->maketext( 'Certificate #[numf,_1]: [_2]', 1 + $bkt_idx, $domains_desc ) );

    return;
}

sub _create_csr ( $key_pem, @domains ) {    ## no critic qw(Proto)
    require Crypt::Perl::PKCS10;
    require Crypt::Perl::PK;

    chomp $key_pem;

    my $key_obj = Crypt::Perl::PK::parse_key($key_pem);

    my $pkcs10 = Crypt::Perl::PKCS10->new(
        key => $key_obj,

        # LE doesn’t require a subject.

        attributes => [
            [
                'extensionRequest',
                [
                    'subjectAltName',
                    map { [ dNSName => $_ ] } @domains,
                ],
            ],
        ],
    );

    return $pkcs10->to_pem();
}

sub _create_order_for_domains ( $self, @domains ) {    ## no critic qw(Prototype)
    my $order;

    my $acme = $self->_get_acme();

    $self->_catch_orders_rate_limit(
        sub {
            $order = Cpanel::SSL::ACME::create_order_for_domains( $acme, @domains );
        }
    );

    return $order;
}

sub _finalize_order_and_confirm ( $self, $order, $csr_pem ) {    ## no critic qw(Prototype)
    my $acme = $self->_get_acme();

    my $status = $acme->finalize_order( $order, $csr_pem );

    while ( $status ne 'valid' ) {
        if ( $status ne 'pending' ) {

            # This should not happen since we’ll have just done
            # successful authz (i.e., DCV) against all domains on
            # the certificate.
            die Cpanel::Exception->create_raw("An ACME order failed finalization (status: $status)! This probably indicates either a server error or an error in AutoSSL’s Let’s Encrypt provider.");
        }

        _sleep_for_poll();

        $status = $acme->poll_order($order);
    }

    return;
}

sub _sleep_for_poll {
    return sleep 1;
}

#----------------------------------------------------------------------

sub SPECS {
    return {
        'DELIVERY_METHOD'                                        => 'api',
        'AVERAGE_DELIVERY_TIME'                                  => 5,
        'RATE_LIMIT_CERTIFICATES_PER_REGISTERED_DOMAIN_PER_WEEK' => 50,
        'VALIDITY_PERIOD'                                        => 90 * 86400,
    };
}

sub ON_START_CHECK($self) {    ## no critic qw(Proto)
    if ( my $state_obj = $self->_get_saved_state_if_should_use() ) {
        my $count = $state_obj->count_domains();

        $self->log( 'info', _locale()->maketext( 'Cached [asis,Let’s Encrypt] [output,abbr,DCV,Domain Control Validation] values: [numf,_1]', $count ) );
    }

    return;
}

sub ON_FINISH_CHECK($self) {    ## no critic qw(Proto)
    if ( my $state_obj = $self->_get_saved_state_if_should_use() ) {

        # Only purge failures rather than all domains because the successes
        # will be valid for long enough that we could reuse them if, e.g.,
        # the user adds a domain that will go on the same certificate.
        $self->log( 'info', _locale()->maketext('Emptying [asis,Let’s Encrypt]’s [output,abbr,DCV,Domain Control Validation] cache …') );

        $state_obj->purge_all();
    }

    return;
}

sub _catch_orders_rate_limit ( $self, $todo_cr ) {    ## no critic qw(Proto)
    Cpanel::Try::try(
        $todo_cr,
        'Cpanel::SSL::ACME::X::RateLimit' => sub {
            my $err      = $@;
            my $acme_err = $err->get_acme_error();

            my $key_id = $self->_get_acme()->key_id();

            # We can tolerate all rate limits other than the one
            # that says we can’t make any more cert orders right now.
            if ( $acme_err && Cpanel::SSL::ACME::LetsEncrypt::error_is_orders_rate_limit($acme_err) ) {

                # Signal to AutoSSL that no further work can be done but that
                # ON_FINISH_CHECK() should NOT fire.
                die Cpanel::Exception::create(
                    'AutoSSL::DeferFurtherWork', '[asis,AutoSSL] failed to create a new certificate order because the server’s [asis,Let’s Encrypt] account ([_1]) has reached its rate limit on certificate orders. [asis,AutoSSL] will defer further action until its next run. You may also contact [asis,Let’s Encrypt] to request a change to this rate limit.',
                    [$key_id]
                );
            }
            else {
                my $err_str = $acme_err ? $acme_err->to_string() : 'unknown';

                my $msg = _locale()->maketext( '[asis,AutoSSL] failed to create a new certificate order because the server’s [asis,Let’s Encrypt] account ([_1]) has reached a rate limit. ([_2]) You may contact [asis,Let’s Encrypt] to request a change to this rate limit.', $key_id, $err_str );

                $self->log( 'warn', $msg );
            }
        },
        'Net::ACME2::X::Generic' => sub {

            # Propagate a Cpanel::Exception so that whether we get
            # a stack trace or not is consistent with the rest of AutoSSL.
            die Cpanel::Exception->create_raw( $@->get_message() );
        },
    );

    return;
}

sub _get_saved_state_if_should_use($self) {    ## no critic qw(Proto)
    return undef if !$self->is_all_users();

    return $self->{'_saved_state'} ||= do {
        my $key_id = $self->_get_acme()->key_id() or die 'Attempt to load saved state without key ID in ACME object!';

        local ( $!, $@ );
        Cpanel::LoadModule::Custom::load_perl_module('Cpanel::SSL::Auto::Provider::LetsEncrypt::SavedState');
        Cpanel::SSL::Auto::Provider::LetsEncrypt::SavedState->new($key_id);
    };
}

*_get_epoch_seconds_if_is_acceptable_expiry_time = *Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend::get_epoch_seconds_if_is_acceptable_expiry_time;

sub _filter_dcv_cached_domains ( $self, $autossl_dcv ) {    ## no critic qw(Proto)
    my @domains_to_dcv;

    my $state_obj = $self->_get_saved_state_if_should_use();

    for my $domain ( $autossl_dcv->get_sorted_domains() ) {
        my ( $expiry, $http_err, $dns_err ) = $state_obj && $state_obj->get_domain_info($domain);

        if ($expiry) {
            if ( my $epoch = _get_epoch_seconds_if_is_acceptable_expiry_time($expiry) ) {
                $self->log( 'success', _locale()->maketext( 'Reusing cached [asis,Let’s Encrypt] [asis,DCV] success: [_1] (expiry: [datetime,_1,datetime_format_short] [asis,UTC])', $domain, $epoch ) );
            }
            else {
                push @domains_to_dcv, $domain;
            }
        }

        # It doesn’t make sense to reuse cases where we only have an
        # HTTP failure (and not a DNS failure) because we’d still have
        # to put them on an order to do the DNS DCV for $domain. Such
        # cases will likely be rare anyway.
        elsif ($dns_err) {
            my $err_count = $http_err ? 2 : 1;

            $self->log( 'info', _locale()->maketext( 'Reusing cached [asis,Let’s Encrypt] [asis,DCV] [numerate,_1,error,errors]: [_2]', $err_count, $domain ) );

            $autossl_dcv->add_http_warning( $domain, $http_err ) if $http_err;
            $autossl_dcv->add_dns_failure( $domain, $dns_err );
        }
        else {
            push @domains_to_dcv, $domain;
        }
    }

    return \@domains_to_dcv;
}

sub _create_acme_dcv_object ( $self, $domains_ar, $dcv_obj ) {    ## no critic qw(Proto)
    my $acme_dcv;

    Cpanel::LoadModule::Custom::load_perl_module('Cpanel::SSL::ACME::DCV');
    $self->_catch_orders_rate_limit(
        sub {
            $acme_dcv = Cpanel::SSL::ACME::DCV->new(
                provider => $self,
                acme     => $self->_get_acme(),
                domains  => $domains_ar,
            );
        },
    );

    if ( !$acme_dcv ) {

        # If we get here that means a rate limit happened that
        # prevented creation of the underlying ACME certificate order,
        # but that rate limit was NOT the orders rate limit (which
        # would have caused an exception). This means we fail DCV
        # since the DCV can’t happen.

        my $str = _locale()->maketext('A rate limit prevents [asis,DCV].');

        # Add to DNS since we interpret DNS DCV failure as a “final”
        # DCV failure.
        $dcv_obj->add_general_failure( $_ => $str ) for @$domains_ar;
    }

    return $acme_dcv;
}

sub _filter_domains_with_valid_dcv ( $self, $domains_ar, $acme_dcv, $autossl_dcv ) {    ## no critic qw(Proto)
    my @domains;

    my $expiry_hr = $acme_dcv->get_domain_validity_expirations(@$domains_ar);

    my $count = 0;

    for my $d ( reverse 0 .. $#$domains_ar ) {
        my $domain = $domains_ar->[$d];

        my $expiry = $expiry_hr->{$domain};
        next if !$expiry;

        my $epoch = _get_epoch_seconds_if_is_acceptable_expiry_time($expiry);
        next if !$epoch;

        splice @$domains_ar, $d, 1;
        $count++;

        $self->log( 'success', _locale()->maketext( '[asis,Let’s Encrypt] [asis,DCV] for “[_1]” is valid until [datetime,_2,datetime_format_short] [asis,UTC].', $domain, $epoch ) );

        $autossl_dcv->add_general_success($domain);
    }

    return $count;
}

# This function implements Let’s Encrypt’s own DCV.
# See the base class for a full description of the interface and the
# problem that it solves.
#
# NB: What is called “$provider_dcv” in other contexts is called here
# “$autossl_dcv” because from this method’s context the object represents
# the AutoSSL framework, whereas outside this module’s context the object
# represents interaction with the provider’s DCV.
#
sub get_vhost_dcv_errors ( $self, $autossl_dcv ) {    ## no critic qw(Proto)

    my $domains_to_dcv_ar = $self->_filter_dcv_cached_domains($autossl_dcv);

    my $domains_left_on_possible_cert = $self->MAX_DOMAINS_PER_CERTIFICATE();

    # Loop logic (assume MAX_DOMAINS_PER_CERTIFICATE == 100):
    #   1) First time through we check 100 domains. 10 fail.
    #   2) 2nd time through we check 10 domains; 5 fail.
    #   3) Next time we check 5 more … and so on, until we reach either
    #      the end of the vhost’s domains list or 100 DCV successes.

    my $state_obj = $self->_get_saved_state_if_should_use();

  DOMAINS_BATCH:
    while ( my @domains = splice( @$domains_to_dcv_ar, 0, $domains_left_on_possible_cert ) ) {
        my $acme_dcv = $self->_create_acme_dcv_object( \@domains, $autossl_dcv ) or do {
            next DOMAINS_BATCH;
        };

        $domains_left_on_possible_cert -= $self->_filter_domains_with_valid_dcv( \@domains, $acme_dcv, $autossl_dcv );

        my ( $http_domains_ar, $dns_domains_ar ) = Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend::split_domains_by_dcv_method( $self, \@domains, $autossl_dcv );

        if (@$http_domains_ar) {
            my @failed = Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend::do_http_dcv( $acme_dcv, $autossl_dcv, $http_domains_ar, $state_obj );

            $domains_left_on_possible_cert -= ( @$http_domains_ar - @failed );

            if (@failed) {
                push @$dns_domains_ar, @failed;

                # Let’s Encrypt requires a new order to switch
                # authz/DCV methods after a first method failed.
                # RFC 8555 doesn’t seem to describe this; in fact,
                # it outlines a retry-challenge behavior, but
                # LE doesn’t support this as of July 2019.
                #
                # In testing, this duplicate order didn’t actually
                # seem to count against the 300-orders rate limit.
                # So, yay. :)
                #
                # Note also that the authzs on this object should
                # not go “stale” because either we’ll verify them
                # below or they’ve already passed via HTTP.

                $acme_dcv = $self->_create_acme_dcv_object( \@domains, $autossl_dcv ) or do {
                    next DOMAINS_BATCH;
                };
            }
        }

        my @dns_failures;

        if (@$dns_domains_ar) {
            @dns_failures = Cpanel::SSL::Auto::Provider::LetsEncrypt::Backend::do_dns_dcv( $acme_dcv, $autossl_dcv, $dns_domains_ar, $state_obj );

            $domains_left_on_possible_cert -= ( @$dns_domains_ar - @dns_failures );
        }

        if ( !@dns_failures ) {
            $self->_set_cached_order( $acme_dcv->get_order_if_no_failures() );
        }
    }

    return;
}

sub _set_cached_order ( $self, $order ) {    ## no critic qw(Proto)
    $self->{'_cached_order'} ||= Cpanel::SSL::Auto::Provider::LetsEncrypt::OrderCache->new();

    $self->{'_cached_order'}->add($order);

    return;
}

sub _get_cached_order ( $self, $domains_ar ) {    ## no critic qw(Proto)
    return $self->{'_cached_order'} && $self->{'_cached_order'}->get($domains_ar);
}

#----------------------------------------------------------------------

my $lh;

sub _locale {
    require Cpanel::Locale;
    return ( $lh ||= Cpanel::Locale->get_handle() );
}

1;
