package Cpanel::UpdateGatherer::modules::Locales;

# cpanel - SOURCES/Locales.pm                      Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use Cpanel::Config::Users          ();
use Cpanel::Config::LoadCpUserFile ();

sub compile {
    my ( $self, $meta ) = @_;

    my %locales = map { $_ => 0 } qw{ar cs da de el es_es es_419 fi fil fr he hu id it ja ko ms nb nl pl pt_br ro ru sv th tr uk vi zh zh_tw};
    $meta->{'locale'} = \%locales;

    foreach my $user ( Cpanel::Config::Users::getcpusers() ) {
        my %cpuser = Cpanel::Config::LoadCpUserFile::load( $user, { 'quiet' => 1 } );
        $meta->{'locale'}{ $cpuser{'LOCALE'} }++;
    }

    _add_check_custom_locales($meta);
    return 1;
}

# used for unit tests
sub __locale_local_dir {
    return '/var/cpanel/locale.local';
}

sub _add_check_custom_locales {
    my ( $self, $meta ) = @_;

    return unless ref $meta eq 'HASH';

    my @custom_locales;
    my $dh;
    if ( opendir( $dh, __locale_local_dir() ) ) {
        while ( my $ls = readdir $dh ) {
            if ( $ls =~ qr{^([0-9a-z_]+)\.yaml$} && -f __locale_local_dir() . '/' . $ls ) {
                push @custom_locales, $1;
            }
        }
        closedir($dh);
    }

    $meta->{'custom_locales'} = [ sort @custom_locales ];

    return 1;
}
1;
