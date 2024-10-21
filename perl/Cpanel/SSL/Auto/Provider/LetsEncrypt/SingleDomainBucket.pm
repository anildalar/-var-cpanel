package Cpanel::SSL::Auto::Provider::LetsEncrypt::SingleDomainBucket;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/SingleDomainBucket.pm
#                                                  Copyright 2020 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use experimental 'signatures';

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::SingleDomainBucket

=head1 SYNOPSIS

    my $bucket = Cpanel::SSL::Auto::Provider::LetsEncrypt::SingleDomainBucket->new( 'home.foo.com' );

=head1 DESCRIPTION

This module provides an interface that’s compatible with
L<Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket> but for a
single domain. This is useful, e.g., for dynamic DNS, where we only
ever want 1 domain per certificate.

=cut

#----------------------------------------------------------------------

=head1 METHODS

=head2 $obj = I<CLASS>->new( $DOMAIN_NAME )

Creates a I<CLASS> instance with domain $DOMAIN_NAME.

=cut

sub new ($class, $domain_name) {
    return bless [$domain_name], $class;
}

sub domains ($self) {
    return [ $self->[0] ];
}

*domain_set_names = *domains;

1;
