package Cpanel::SSL::Auto::Provider::LetsEncrypt::RegisteredDomains;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/RegisteredDomains.pm
#                                                 Copyright(c) 2016 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

=pod

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::RegisteredDomains - A utility module for handling Let's Encrypt registered domains

=head1 DESCRIPTION

A utility module for grouping vhosts by registered domain for Let's Encrypt

=cut

use strict;
use warnings;

use Cpanel::PublicSuffix      ();
use Cpanel::AcctUtils::Domain ();

use Cpanel::AcctUtils::Domain                                       ();
use Cpanel::SSL::Auto::Provider::LetsEncrypt                        ();
use Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucketCollection ();

my $tld_cache;

=pod

=head1 SUB NAME

get_certificate_buckets_grouped_by_registered_domain

=head1 DESCRIPTION

 This function takes in a local DCV checked mapping of vhosts and domains
that have already passed our local DCV check. The vhosts will be sorted
by registered domain and assigned a certificate that will reduce the
amount of extra certificates created for the same registered domain.

=head1 PARAMETERS

=over 4

=item user - The name of the user for which to group the buckets for

=item vhost_maps - domain_to_vhost and vhost_to_domains mappings fitting the following form:

 {
     domain_to_vhost => {
         domain.tld => domain.tld,
         www.domain.tld => domain.tld,
         sub.domain.tld => sub.domain.tld,
         www.sub.domain.tld => sub.domain.tld,
     },
     vhost_to_domains => {
         domain.tld => [
             domain.tld,
             www.domain.tld
         ],
         sub.domain.tld => [
             sub.domain.tld,
             www.sub.domain.tld
         ]
     }
 }

=back

=head1 RETURN

An arrayref of Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket objects that represent the domains and vhosts
that should be put onto a certificate. This is fitting the following form:

 [
    bless{ ... }, Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket,
    bless{ ... }, Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket,
 ]

=cut

sub get_certificate_buckets_grouped_by_registered_domain {
    my ( $user, $vhost_maps ) = @_;

    my $combined_vhost_maps = _group_vhosts_by_registered_domain($vhost_maps);

    my @certificates;

    my $user_main_domain = Cpanel::AcctUtils::Domain::getdomain($user);

    my $vhost_bucket_collection = Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucketCollection->new();

    # if the user's main domain is listed in with the domains it passed our internal DCV check.. we should prioritize that domain
    my @vhosts = ( ( $combined_vhost_maps->{domain_to_vhost}{$user_main_domain} ? $user_main_domain : () ), sort keys %{ $combined_vhost_maps->{vhost_to_domains} } );
    for my $vhost (@vhosts) {
        next if $vhost_bucket_collection->contains_vhost($vhost);

        $vhost_bucket_collection->add_vhost_to_bucket( $vhost, $combined_vhost_maps->{vhost_to_domains}{$vhost} );
        _add_all_associated_vhosts( $vhost, $combined_vhost_maps, $vhost_bucket_collection );

        # We've hit a logical stopping point. As to not crowd the certificates with unrelated domains
        # lets close the current buckets and start adding more for the next logical grouping
        $vhost_bucket_collection->close_current_buckets();
    }

    return [ $vhost_bucket_collection->get_all_buckets() ];
}

##############################################################
#  Name
#    _add_all_associated_vhosts
#
#  Description
#    This function will find all the vhosts associated to the passed in vhost
#    by registered domain. It will then take those vhosts and determine which
#    certificate 'bucket' to put them in based upon number of domains and our soft domain
#    limit. Once it finds or creates a 'bucket' it will add all the vhosts to that bucket.
#
#  Parameters
#    vhost
#      The name of the vhost to find associated vhosts for.
#    combined_vhost_maps
#      A hashref containing four mappings, domain => vhost, vhost => domains, registered_domain => vhosts, vhost => registered domains
#      These domains should be ones that have passed our local DCV check
#        {
#            domain_to_vhost => {
#                domain.tld => domain.tld,
#                www.domain.tld => domain.tld,
#                sub.domain.tld => sub.domain.tld,
#                www.sub.domain.tld => sub.domain.tld,
#            },
#            vhost_to_domains => {
#                domain.tld => [
#                    domain.tld,
#                    www.domain.tld
#                ],
#                sub.domain.tld => [
#                    sub.domain.tld,
#                    www.sub.domain.tld
#                ]
#            },
#            registered_domain_to_vhosts => {
#               domain.tld => {
#                 domain.tld => 1,
#                 sub.domain.tld => 1,
#                }
#            },
#            vhost_to_registered_domains => {
#                domain.tld => {
#                    domain.tld => 1,
#                },
#                sub.domain.tld => {
#                    domain.tld => 1,
#                },
#            }
#        }
#    vhost_bucket_collection
#      A VhostBucketCollection object representing the already created vhost buckets to act upon.
#
#  Returns
#    Nothing
#
sub _add_all_associated_vhosts {
    my ( $vhost, $combined_vhost_maps, $vhost_bucket_collection ) = @_;

    my @associated_vhosts = _get_associated_vhosts( $vhost, $combined_vhost_maps );
    for my $associated_vhost (@associated_vhosts) {
        next if $vhost_bucket_collection->contains_vhost($associated_vhost);

        $vhost_bucket_collection->add_vhost_to_bucket( $associated_vhost, $combined_vhost_maps->{vhost_to_domains}{$associated_vhost} );
    }

    return;
}

sub _get_associated_vhosts {
    my ( $vhost, $combined_vhost_maps ) = @_;

    my %associated_vhosts = map {
        map { $vhost ne $_ ? ( $_ => 1 ) : () }
          keys %{ $combined_vhost_maps->{registered_domain_to_vhosts}{$_} }
    } keys %{ $combined_vhost_maps->{vhost_to_registered_domains}{$vhost} };

    return keys %associated_vhosts;
}

# This takes the vhost_to_domains and domain_to_vhost mappings and creates the
# combined_vhost_map which adds on the registered_domain_to_vhosts and vhost_to_registered_domains mappings
# Fits the form (input):
# {
#     domain_to_vhost => {
#         domain.tld => domain.tld,
#         www.domain.tld => domain.tld,
#         sub.domain.tld => sub.domain.tld,
#         www.sub.domain.tld => sub.domain.tld,
#     },
#     vhost_to_domains => {
#         domain.tld => [
#             domain.tld,
#             www.domain.tld
#         ],
#         sub.domain.tld => [
#             sub.domain.tld,
#             www.sub.domain.tld
#         ]
#     }
# }
# This function returns a data structure like this (output):
# {
#    'registered_domain_to_vhosts' => {
#                                       'parked.tld' => {
#                                                       'domain.tld' => 1
#                                                     },
#                                       'domain.tld' => {
#                                                       'something.domain.tld' => 1,
#                                                       'another.domain.tld' => 1,
#                                                       'domain.tld' => 1
#                                                     },
#                                        ...
#                                     },
#    'vhost_to_registered_domains' => {
#                                       'old.another.co.uk' => {
#                                                                'another.co.uk' => 1
#                                                              },
#                                       'a.another.co.uk' => {
#                                                              'another.co.uk' => 1
#                                                            },
#                                       'domain.tld' => {
#                                                         'parked.tld' => 1,
#                                                         'domain.tld' => 1
#                                                       },
#                                        ...
#                                     },
#    'vhost_to_domains' => {
#                            'a.another.co.uk' => [
#                                                   'a.another.co.uk',
#                                                   'www.a.another.co.uk'
#                                                 ],
#                            'domain.tld' => [
#                                              'parked.tld',
#                                              'www.parked.tld',
#                                              'parked.domain.tld',
#                                              'www.parked.domain.tld'
#                                            ],
#                            ...
#                          },
#    'domain_to_vhost' => {
#                           'parked.domain.tld' => 'domain.tld',
#                           'another.domain.tld' => 'another.domain.tld',
#                           'www.parked.domain.tld' => 'domain.tld',
#                           ...
#                         }
#  };
sub _group_vhosts_by_registered_domain {
    my ($vhost_maps) = @_;

    my %registered_domain_to_vhosts = ();
    my %vhost_to_registered_domains = ();

    for my $domain ( keys %{ $vhost_maps->{domain_to_vhost} } ) {
        my $registered_domain = _get_registered_domain_from_domain($domain);
        my $vhost             = $vhost_maps->{domain_to_vhost}{$domain};
        $registered_domain_to_vhosts{$registered_domain}{$vhost} = 1;
        $vhost_to_registered_domains{$vhost}{$registered_domain} = 1;
    }

    return {
        registered_domain_to_vhosts => \%registered_domain_to_vhosts,
        vhost_to_registered_domains => \%vhost_to_registered_domains,
        ( map { $_ => $vhost_maps->{$_} } keys %$vhost_maps ),
    };
}

sub _get_registered_domain_from_domain {
    my ($domain) = @_;

    my ( $tld, @remainder ) = _get_tld_and_remaining_labels_from_domain($domain);
    die "Invalid Domain!" if !@remainder;    # paranoia - we should never trip this

    return join( '.', ( $remainder[-1], $tld ) );
}

sub _get_tld_and_remaining_labels_from_domain {
    my ($domain) = @_;

    $tld_cache ||= {};

    if ( $tld_cache->{$domain} ) {
        return ($domain);
    }

    if ( !exists $tld_cache->{$domain} && Cpanel::PublicSuffix::domain_isa_tld($domain) ) {
        $tld_cache->{$domain} = 1;
        return ($domain);
    }
    else {
        $tld_cache->{$domain} = 0;
    }

    my @labels = _get_labels_from_domain($domain);
    my @remainder;
    while (@labels) {
        push @remainder, shift @labels;
        my $test_domain = join( '.', @labels );

        return ( $test_domain, @remainder ) if $tld_cache->{$test_domain};
        if ( !exists $tld_cache->{$test_domain} ) {
            if ( Cpanel::PublicSuffix::domain_isa_tld($test_domain) ) {
                $tld_cache->{$test_domain} = 1;
                return ( $test_domain, @remainder );
            }
            else {
                $tld_cache->{$test_domain} = 0;
            }
        }
    }

    return;
}

sub _get_labels_from_domain {
    my ($domain) = @_;

    local ( $@, $! );
    require Net::DNS::Question;
    my $question = Net::DNS::Question->new($domain);
    return $question->{'qname'}->label();
}

1;
