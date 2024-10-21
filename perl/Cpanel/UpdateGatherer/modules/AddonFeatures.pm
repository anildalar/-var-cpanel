package Cpanel::UpdateGatherer::modules::AddonFeatures;

# cpanel - SOURCES/AddonFeatures.pm                Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use Cpanel::Features ();

sub compile {
    my ( $self, $meta ) = @_;
    _add_addon_feature_metadata($meta);
    return 1;
}

sub _add_addon_feature_metadata {
    my ($meta) = @_;

    return unless ref $meta eq 'HASH';

    my @addons = Cpanel::Features::load_addon_feature_descs();
    my %data;

    foreach my $addon (@addons) {
        my ( $id, $name ) = @$addon;
        $data{$id} = $name;
    }

    $meta->{addon_features} = \%data;

    return;
}
1;
