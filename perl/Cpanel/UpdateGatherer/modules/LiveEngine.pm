package Cpanel::UpdateGatherer::modules::LiveEngine;

# cpanel - SOURCES/LiveEngine.pm                   Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use Cpanel::UpdateGatherer::Std;    # after Moo

use File::Find ();

# view: https://api.docs.cpanel.net/guides/guide-to-the-liveapi-system

sub compile ( $class, $meta ) {

    return _add_metrics($meta);
}

sub supported_directories() {

    # softaculous is installing to whostmgr/docroot
    return [
        qw{
          /usr/local/cpanel/whostmgr/docroot
          /usr/local/cpanel/base/frontend
          /usr/local/cpanel/base/3rdparty
        }
    ];
}

sub supported_engines() {
    return {
        perl   => 'pl',
        cgi    => 'cgi',
        ruby   => 'rb',
        python => 'py',
        php    => 'php',
    };
}

sub _to_ignore() {

    # doing our best to avoid reporting files from these locations
    return [
        map { "/usr/local/cpanel/base/frontend/$_" }
          qw{
          demo\.live\.php
          jupiter/integration_examples/.*
          jupiter/resource_usage/.*
          jupiter/lveversion/.*
          }
    ];
}

sub _root_dir {    # for testing
    return '/usr/local/cpanel';
}

sub _add_metrics ($meta) {

    my $supported_engines = supported_engines();

    my %counter     = map { $_ => 0 } keys $supported_engines->%*;
    my %ext_to_name = reverse $supported_engines->%*;

    my $re           = _build_re();
    my @ignore_rules = _to_ignore()->@*;

    my %directories_detected;

    my $root = _root_dir();

    my $search = sub {
        my $f = $File::Find::name;
        return if -d $f || !-e $f;

        return unless $f =~ $re;
        my $ext = $1;

        return if grep { $f =~ m{^$_$} } @ignore_rules;

        my ($dir) = $f =~ m{^$root/(.+)/[^/]+$};
        $directories_detected{$dir}++ if length $dir;

        my $type = $ext_to_name{$ext} // $ext;

        ++$counter{$type};
    };

    foreach my $dir ( supported_directories()->@* ) {
        next unless -d $dir;
        File::Find::find(
            {
                follow   => 0,
                no_chdir => 1,
                wanted   => $search,
            },
            $dir
        );
    }

    $meta->{'liveengine'} = {
        'locations' => [ sort keys %directories_detected ],
        'usage'     => \%counter,
    };

    return 1;
}

sub _build_re() {

    my $all_ext = join( '|', sort values supported_engines->%* );
    return qr{\Q.live\E\.?($all_ext)$};
}

1;
