package Cpanel::SSL::ACME::DCV;

# cpanel - Cpanel/SSL/ACME/DCV.pm                  Copyright 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::ACME::DCV - DCV for ACME

=head1 SYNOPSIS

    my $dcv = Cpanel::SSL::ACME::DCV->new(
        acme => $acme_obj,
        domains => \@domains,
    );

    $dcv->attempt_http( $username, $callback, @subset_of_domains );

    $dcv->attempt_dns( $callback, @subset_of_domains );

    my $order_obj = $dcv->get_order_if_no_failures();

    my $expiry = $dcv->get_authz_expiry( $domain );

=head1 DESCRIPTION

This class represents a batch of DCVs for L<the v2 ACME protocol|https://tools.ietf.org/html/rfc8555>.

Each batch of DCVs happens via creation of an ACME certificate order.
If (but only if) all DCVs succeed, the order may be finalized to request
that a certificate be issued.

=head1 BACKGROUND

The workflow of the initial “draft” ACME protocol involved doing DCV
(aka “authorization” in ACME) prior to a certificate request. This simple
workflow was easy to implement.

The finalized ACME protocol (documented in the aforementioned RFC) added an
additional step: prior to DCV, a certificate “order” must be created; only
after that “order” exists can DCV happen. (Once the DCVs are done, the order is
“finalized”, which constitutes an actual request for certificate issuance.)

It is anticipated that rate limits may require domains on different web vhosts
to be combined to maximize SSL coverage, such as cPanel’s Let’s Encrypt
plugin does via its C<get_certificate_buckets_grouped_by_registered_domain()>
function. So the ACME order that this module creates may or may not be useful
to request certificate issuance.

=cut

#----------------------------------------------------------------------

use Cpanel::SSL::ACME ();
use Cpanel::Try       ();

use constant {
    _TIMEOUT => {
        'http-01' => 30,
        'dns-01'  => 300,
    },
};

#----------------------------------------------------------------------

=head1 METHODS

=head2 I<CLASS>->new( %OPTS )

Instantiates this class. %OPTS are:

=over

=item * C<acme> - a L<Net::ACME2> instance

=item * C<domains> - reference to an array of domains that will be
part of the DCV batch

=item * C<provider> - a L<Cpanel::SSL::Auto::Provider::LetsEncrypt> instance

=back

=cut

# acme, domains
sub new ( $class, %opts ) {
    $opts{'_order'} = Cpanel::SSL::ACME::create_order_for_domains( $opts{'acme'}, @{ $opts{'domains'} } );

    return bless \%opts, $class;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->attempt_dns( $DOMAIN_CALLBACK, @DOMAINS )

Attempts DNS-based DCV for the given @DOMAINS, which B<MUST> include
no domains not given to the invocation of C<new()> that created I<OBJ>.

As each DCV completes, $DOMAIN_CALLBACK is invoked with two arguments:
the domain, and the failure reason (or undef if DCV succeeded).

This calls into cPanel & WHM’s C<Cpanel::DnsUtils::Batch::set_for_type()>
and C<Cpanel::SSL::DCV::DNS::check_multiple_nonfatal()> functions to
effect the necessary DNS changes.

=cut

sub attempt_dns ( $self, $callback, @domains ) {
    my $acme = $self->{'acme'};

    my @txt_records;

    my %domain_challenge;

    for my $domain (@domains) {
        my $challenge = $self->_get_domain_challenge( $domain, 'dns-01' ) or do {

            # If we timed out the HTTP DCV, LE might keep going with
            # the checks and actually convert the authz to “valid”.
            # In that case, we won’t get a DNS challenge. Let’s detect
            # that case here.
            my $authz = $self->_get_domain_authz($domain);
            if ( 'valid' eq $authz->status() ) {
                my @ctypes = map { $_->type() } $authz->challenges();

                $self->{'provider'}->log( info => "“$domain” passed DCV (challenge: @ctypes) after initial HTTP failure/timeout." );
                $callback->( $domain, undef, 'http' );
            }
            else {
                $callback->( $domain, "No “dns-01” challenge given!" );
            }

            next;
        };

        $domain_challenge{$domain} = $challenge;

        my $authz_domain = $domain =~ s<\A\*\.><>r;

        my $dns_name  = $challenge->get_record_name() . ".$authz_domain";
        my $rec_value = $challenge->get_record_value($acme);

        push @txt_records, [ $dns_name => $rec_value ];
    }

    if (@txt_records) {
        require Cpanel::DnsUtils::Batch;
        Cpanel::DnsUtils::Batch::set_for_type( 'TXT', \@txt_records );

        # This is necessary for contexts (e.g., DNS clustering)
        # where DNS changes may not propagate immediately.
        _wait_for_txt_records( \@txt_records );

        $acme->accept_challenge($_) for values %domain_challenge;

        $self->_poll_domain_authzs( \%domain_challenge, $callback, 'dns-01' );
    }

    return;
}

sub _wait_for_txt_records {
    my ($txt_records_ar) = @_;

    my %queries = map { ( $_->[0] => [ 'TXT', $_->[1] ] ) } @$txt_records_ar;

    require Cpanel::SSL::DCV::DNS;
    Cpanel::SSL::DCV::DNS::check_multiple_nonfatal(
        queries => \%queries,
    );

    return;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->attempt_http( $USERNAME, $DOMAIN_CALLBACK, @DOMAINS )

Like C<attempt_dns()> but does HTTP-based DCV instead of DNS-based DCV,
and this uses C<Cpanel::WebVhosts::get_docroot_for_domain()> from the
mainline cPanel & WHM code rather than the DNS-setting functions.

This also requires that a $USERNAME be given before @DOMAINS. The HTTP
resources will be created and removed from the filesystem as this user.

This depends on L<Cpanel::AccessIds::ReducedPrivileges>.

=cut

sub attempt_http ( $self, $username, $callback, @domains ) {

    require Cpanel::AccessIds::ReducedPrivileges;
    my $privs = Cpanel::AccessIds::ReducedPrivileges->new($username);

    # This extra block is meant to ensure that any Net::ACME2 handler
    # objects are both created and DESTROYed under full setuid.
    {
        my %domain_handler;

        my $acme = $self->{'acme'};

        for my $domain (@domains) {
            my $challenge = $self->_get_domain_challenge( $domain, 'http-01' ) or do {

                # With Let’s Encrypt, anyway, this should not happen:
                $callback->( $domain, "No “http-01” challenge given!" );

                next;
            };

            require Cpanel::WebVhosts;
            my $docroot = Cpanel::WebVhosts::get_docroot_for_domain($domain) or do {

                # This also should not happen; if it does, there’s likely
                # a misconfiguration or a bug in cPanel & WHM.
                $callback->( $domain, "No HTTP document root found!" );

                next;
            };

            $domain_handler{$domain} = $challenge->create_handler( $acme, $docroot );

            $acme->accept_challenge($challenge);
        }

        $self->_poll_domain_authzs( \%domain_handler, $callback, 'http-01' );
    }

    return;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->get_domain_validity_expirations( @DOMAINS )

Returns a hash reference that correlates domains with the times given
for which those domains’ authorizations remain valid. Times are given
as the ACME server gave them (i.e., RFC 3339).

Any @DOMAINS for which the ACME server does not indicate an existing
valid authorization will be omitted from the returned hash reference.

=cut

sub get_domain_validity_expirations ( $self, @domains ) {
    my %valid_expiry;

    for my $domain (@domains) {
        my $authz        = $self->_get_domain_authz($domain);
        my $authz_status = $authz->status();

        if ( $authz_status ne 'pending' ) {
            if ( $authz_status eq 'valid' ) {
                $valid_expiry{$domain} = $authz->expires();
            }
            else {
                warn "$domain’s ACME authorization has an unexpected status ($authz_status)!";
            }
        }
    }

    return \%valid_expiry;
}

#----------------------------------------------------------------------

=head2 I<OBJ>->get_authz_expiry( $DOMAIN )

A single-domain variant of C<get_domain_validity_expirations()>.
Returns the date itself.

=cut

sub get_authz_expiry ( $self, $domain ) {    ## no critic qw(Proto)
    my $authz = $self->_get_domain_authz($domain);
    return $authz->expires();
}

#----------------------------------------------------------------------

=head2 I<OBJ>->get_order_if_no_failures()

Returns the underlying L<Net::ACME2::Order> object.

Note that this is B<only> useful if
that order can be finalized—i.e., if all of its domains have passed DCV.
As a result, any call into this function made while one of the
order authzs is C<invalid> will result in a thrown exception.

=cut

sub get_order_if_no_failures($self) {    ## no critic qw(Prototype)
    for my $d ( @{ $self->{'domains'} } ) {
        my $status = $self->_get_domain_authz($d)->status();

        next if $status eq 'valid';
        next if $status eq 'pending';

        die "Call to fetch order object, but domain “$d” has status “$status”!";
    }

    return $self->{'_order'};
}

#----------------------------------------------------------------------

sub _poll_domain_authzs ( $self, $domain_lookup_hr, $callback, $challenge_type ) {
    my $acme = $self->{'acme'};

    my $timeout = _TIMEOUT()->{$challenge_type};

    my $timeout_at = _time() + $timeout;

    while (%$domain_lookup_hr) {
        if ( time < $timeout_at ) {
            _sleep_for_poll();    # Even on the first try, delay for LE to poll.

            for my $domain ( keys %$domain_lookup_hr ) {
                my $authz = $self->_get_domain_authz($domain);

                my $status = $acme->poll_authorization($authz);

                next if $status eq 'pending';

                delete $domain_lookup_hr->{$domain};

                my $failure_reason;

                if ( $status eq 'invalid' ) {
                    my $challenge = $self->_get_domain_challenge( $domain, $challenge_type );
                    my $err_obj   = $challenge->error();

                    # The ternary is just in case, for whatever reason,
                    # we ever get a failed challenge that lacks an error.
                    $failure_reason = $err_obj ? $err_obj->to_string() : 'unknown';
                }
                elsif ( $status ne 'valid' ) {

                    # Should not happen; indicates an unrecognized behavior
                    # from the ACME server.
                    $failure_reason = "Unknown authz status: $status";
                }

                $callback->( $domain, $failure_reason );
            }
        }
        else {
            $callback->( $_, "Timeout after $timeout seconds!" ) for keys %$domain_lookup_hr;
            %$domain_lookup_hr = ();
        }
    }

    return;
}

# stubbed in tests
sub _time {
    return time;
}

# stubbed in tests
sub _sleep_for_poll {
    sleep 1;
}

sub _get_domain_challenge ( $self, $domain, $type ) {
    my $authz = $self->_get_domain_authz($domain);

    my ($challenge) = grep { $_->type() eq $type } $authz->challenges();

    return $challenge;
}

sub _get_domain_authz ( $self, $domain ) {
    my $order = $self->{'_order'};

    # NOTE: This logic assumes that there is exactly one authz object
    # per identifier (domain) in the order … which RFC 8555 specifically
    # says need not always be the case, but which Let’s Encrypt, anyway,
    # does. If it becomes a problem later we can work out a solution.

    $self->{'_domain_authz'} ||= $self->_build_domain_authz_cache();

    # die() here because that likely means there’s a logic error.
    return $self->{'_domain_authz'}{$domain} || die "No authz given for domain “$domain”!";
}

sub _build_domain_authz_cache($self) {    ## no critic qw(Proto)
    my $order = $self->{'_order'};

    my @authzs = map { $self->{'acme'}->get_authorization($_) } $order->authorizations();

    my %h;

    for my $authz (@authzs) {
        my $real_domain = $authz->wildcard() ? '*.' : q<>;
        $real_domain .= $authz->identifier()->{'value'};

        $h{$real_domain} = $authz;
    }

    return \%h;
}

1;
