package Cpanel::SSL::ACME;

# cpanel - Cpanel/SSL/ACME.pm                      Copyright 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::ACME - Convenience wrappers around L<Net::ACME2> methods

=head1 SYNOPSIS

    my $order = Cpanel::SSL::ACME::create_order_for_domains(
        $acme_obj,
        @domains,
    );

=cut

#----------------------------------------------------------------------

use Cpanel::LoadModule::Custom ();
use Cpanel::Try                ();

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $order = create_order_for_domains( $ACME, @DOMAINS )

Creates an ACME order for the given @DOMAINS, converting that array into
the needed argument to the $ACME’s C<create_order()> method. The return
is the same as from C<create_order()>.

If a L<Net::ACME2::X::ACME> rate limit error occurs, a
L<Cpanel::SSL::ACME::X::RateLimit>
instance will be thrown. Any other failure propagates as usual.

=cut

sub create_order_for_domains ( $acme, @domains ) {
    my $order;

    Cpanel::Try::try(
        sub {
            $order = $acme->create_order(
                identifiers => [ map { { type => 'dns', value => $_ } } @domains ],
            );
        },
        'Net::ACME2::X::ACME' => sub {
            my $err = $@;

            if ( my $acme_err = $err->get('acme') ) {
                if ( $acme_err->type() eq 'urn:ietf:params:acme:error:rateLimited' ) {
                    Cpanel::LoadModule::Custom::load_perl_module('Cpanel::SSL::ACME::X::RateLimit');
                    die Cpanel::SSL::ACME::X::RateLimit->new($acme_err);
                }
            }

            local $@ = $err;
            die;
        },
    );

    return $order;
}

1;
