package Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucketCollection;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/VhostBucketCollection.pm
#                                                 Copyright(c) 2016 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

=pod

=encoding utf-8

=head1 MODULE NAME

Cpanel::SSL::Auto::LetsEncrypt::VhostBucketCollection - A collection of size limited virtual host groupings or "buckets".

=head1 DESCRIPTION

A collection of size limited virtual host groupings henceforth known as 'vhost buckets' or 'buckets'.
The size in question here is the total number of domains in the bucket. The object supports a new bucket threshold
and a size limit on number of domains in a bucket. When the threshold is reached a new bucket is created.
When a size limit is reached no more domains will be added to the bucket. We won't add the extra/left over domains
to another bucket in this case, since that would split the domains on the virtual host. Each virtual host must be
in a single bucket. Multiple virtual hosts can be in a single bucket.

=cut

use strict;
use warnings;

use Try::Tiny;

use Call::Context ();

use Cpanel::Exception ();

use Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants ();

sub new {
    my ( $class, %OPTS ) = @_;

    my $bucket_size      = $OPTS{max_bucket_size}      || Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants->MAX_DOMAINS_PER_CERTIFICATE();
    my $bucket_threshold = $OPTS{new_bucket_threshold} || Cpanel::SSL::Auto::Provider::LetsEncrypt::Constants->SOFT_MAX_DOMAINS_PER_CERTIFICATE();

    return bless {
        _bucket_size        => $bucket_size,
        _bucket_threshold   => $bucket_threshold,
        _buckets            => [],
        _contained_vhosts   => {},
        _start_bucket_index => 0,
    };
}

sub get_all_buckets {
    my ($self) = @_;

    Call::Context::must_be_list();

    return @{ $self->{_buckets} };
}

sub get_max_bucket_size {
    my ($self) = @_;

    return $self->{_bucket_size};
}

sub get_bucket_threshold {
    my ($self) = @_;

    return $self->{_bucket_threshold};
}

sub contains_vhost {
    my ( $self, $vhost ) = @_;

    return $self->{_contained_vhosts}{$vhost} || 0;
}

sub get_contained_vhosts {
    my ($self) = @_;

    return [ keys %{ $self->{_contained_vhosts} } ];
}

=pod

=head1 SUB NAME

add_vhost_to_bucket

=head1 DESCRIPTION

This function will add all the domains on a specified vhost to a 'bucket'.
If a vhost has enough domains that they would put the 'bucket' over the max bucket
size, then only the shortest domains will be added up to the maximum.

=head1 PARAMETERS

=over 4

=item vhost - The name of the vhost to add to a bucket.

=item domains_ar - An arrayref containing the domains contained by the vhost.

=back

=head1 RETURN

The number of domains added as an integer.

=cut

sub add_vhost_to_bucket {
    my ( $self, $vhost, $domains_ar ) = @_;

    my $bucket        = $self->get_bucket_to_fit_domains( scalar @$domains_ar );
    my $domains_added = $bucket->add_vhost( $vhost, $domains_ar );

    $self->{_contained_vhosts}{$vhost} = 1;

    return $domains_added;
}

=pod

=head1 SUB NAME

get_bucket_to_fit_domains

=head1 DESCRIPTION

This function will find the best certificate 'bucket' that exists or create
a new one depending on how many domains are left in the bucket before the
SOFT_MAX_DOMAINS_PER_CERTIFICATE. This function also respects 'closed' buckets and will not
return a closed bucket.


=head1 PARAMETERS

=over 4

=item vhost_size - The number of domains in the current vhost or vhosts that need to be added to a bucket

=back

=head1 RETURN

A reference to the bucket with enough space left (new or previously used) to fit the vhost in question

=cut

sub get_bucket_to_fit_domains {
    my ( $self, $vhost_size ) = @_;

    # Try to find a bucket with enough room left..
    for ( my $index = $self->{_start_bucket_index}; $index < scalar @{ $self->{_buckets} }; $index++ ) {

        # Due to speed of serving certificates we don't really want certs with more domains than the bucket threshold,
        # but this may mean we'll have more buckets than the 20 which is the rate limit 'Certificates/Domains'
        # found at https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769
        # This means that we may not fulfull all the cert requests for their domains if they have more than
        # 20 * (bucket threshold) domains due to the rate limit.
        if ( $self->{_buckets}->[$index]->domain_count() == 0 || $self->{_buckets}->[$index]->threshold_domains_left() >= $vhost_size ) {
            return $self->{_buckets}->[$index];
        }
    }

    # No buckets were big enough, so make a new bucket
    push @{ $self->{_buckets} }, $self->_make_new_bucket();

    return $self->{_buckets}->[-1];
}

=pod

=head1 SUB NAME

close_current_buckets

=head1 DESCRIPTION

This function will 'close' all the current buckets in the collection. Sometimes in our usage we don't want to
add more vhosts to the current buckets to establish better logical groupings. In this instance, we'd close
the buckets and allow for a new bucket to be created to add more logical space for vhosts.


=head1 PARAMETERS

NONE

=head1 RETURN

NONE

=cut

sub close_current_buckets {
    my ($self) = @_;

    $self->{_start_bucket_index} = $#{ $self->{_buckets} } + 1;
    return;
}

sub _make_new_bucket {
    my ($self) = @_;

    return Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket->new(
        max_bucket_size      => $self->{_bucket_size},
        new_bucket_threshold => $self->{_bucket_threshold},
    );
}

#------------------------------------------------------------------------------------------------------

package Cpanel::SSL::Auto::Provider::LetsEncrypt::VhostBucket;

sub new {
    my ( $class, %OPTS ) = @_;

    for my $key (qw( max_bucket_size new_bucket_threshold )) {
        die "Need the parameter '$key'!" if !defined $OPTS{$key};
    }

    return bless {
        '_bucket_size'      => $OPTS{max_bucket_size},
        '_bucket_threshold' => $OPTS{new_bucket_threshold},
        '_domain_count'     => 0,
        '_domains'          => {},
        '_vhosts'           => {},
    }, $class;
}

sub domain_count {
    my ($self) = @_;

    return $self->{_domain_count};
}

sub max_domains_left {
    my ($self) = @_;

    return $self->{_bucket_size} - $self->{_domain_count};
}

sub threshold_domains_left {
    my ($self) = @_;

    my $count = $self->{_bucket_threshold} - $self->{_domain_count};
    return $count > 0 ? $count : 0;
}

sub contains_vhost {
    my ( $self, $vhost ) = @_;

    return $self->{_vhosts}{$vhost} || 0;
}

sub domains {
    my ($self) = @_;

    return [ keys %{ $self->{_domains} } ];
}

sub vhosts {
    my ($self) = @_;

    return [ keys %{ $self->{_vhosts} } ];
}

*domain_set_names = *vhosts;

sub add_vhost {
    my ( $self, $vhost, $domains_ar ) = @_;

    # It's true we make new buckets at the bucket threshold, but an individual vhost may have
    # more than bucket size domains.
    my $domains_left = $self->max_domains_left();

    my $domains_added = 0;

    # Make sure we do this in shortest -> longest domain in case there isn't enough room in the bucket for the whole vhost
    for my $domain ( map { $_->[0] } sort { $a->[1] <=> $b->[1] } map { [ $_, length($_) ] } @$domains_ar ) {
        last if $domains_added == $domains_left;
        if ( !$self->{_domains}{$domain} ) {
            $self->{_domains}{$domain} = 1;
            $self->{_domain_count}++;
            $domains_added++;
        }
    }

    $self->{_vhosts}{$vhost} = 1;

    return $domains_added;
}

1;
