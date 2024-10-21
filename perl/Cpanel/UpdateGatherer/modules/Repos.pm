package Cpanel::UpdateGatherer::modules::Repos;

# cpanel - SOURCES/Repos.pm                        Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use Cpanel::UpdateGatherer::Std;

use Cpanel::Exception ();
use Cpanel::LoadFile  ();
use File::Basename    ();

use constant DEBIAN_REPOS_D => q[/etc/apt/sources.list.d];
use constant YUM_REPOS_D    => q[/etc/yum.repos.d];

=head1 NAME

Cpanel::UpdateGatherer::modules::Repos

=head1 SYNOPSIS

    use Cpanel::UpdateGatherer::modules::Repos ();

    my $meta = {};
    Cpanel::UpdateGatherer::modules::Repos->compile($meta);

=head1 DESCRIPTION

Module for collecting RedHat Yum or Debian repositories setup on a server.

=head1 RETURNS

If the function returns successfully, entry for repo contains a list
of all repositories setup on the server. (enabled or not)

Yum Repositories

    {
        "repos": [
            {
                "name": "extra",
                "label": "CentOS-$releasever - Extra",
                "baseurl": "http://mirror.centos.org/centos/$releasever/extras/$basearch/",
                "enabled": 1,
                "file": "centos-extras.repo"
            },
            {
                "name": "another",
                "label": "Another Repo",
                "mirrorurl": "ttp://mirrorlist.centos.org/...",
                "enabled": 0,
                "file": "another.repo"
            },
            ....
        ],
    }

Debian Repositories
    {
        "repos": [
                {
                    'components'   => 'components',
                    'distribution' => 'distro',
                    'file'         => 'sources.list',
                    'url'          => 'https://main.repo/ubuntu/'
                },
                {
                    'components'   => 'main restricted',
                    'distribution' => 'focal',
                    'file'         => 'first.list',
                    'url'          => 'https://repo.first/ubuntu/'
                },
            ....
        ],
    }

=cut

sub compile ( $, $meta ) {
    die 'Unable to parse meta variable' if !ref $meta;

    # Cpanel::OS::base_distro() eq 'rhel'
    if ( use_yum_packages() ) {
        $meta->{repos} = _get_all_yum_repos();
    }

    # Cpanel::OS::base_distro() eq 'debian'
    elsif ( use_debian_packages() ) {
        $meta->{repos} = _get_all_debian_repos();
    }

    $meta->{repos} //= [];

    return 1;
}

sub use_yum_packages() {

    # try to use the source of truth if available
    my $is_rhel = eval { require Cpanel::OS; Cpanel::OS::base_distro() eq 'rhel' };

    # fallback when Cpanel::OS is not available
    $is_rhel = -d YUM_REPOS_D if $@;

    return $is_rhel;
}

sub use_debian_packages() {

    # try to use the source of truth if available
    my $is_debian = eval { require Cpanel::OS; Cpanel::OS::base_distro() eq 'debian' };

    # fallback when Cpanel::OS is not available
    $is_debian = -d DEBIAN_REPOS_D if $@;

    return $is_debian;
}

sub _get_all_yum_repos() {

    my $repo_dir = YUM_REPOS_D;

    return unless -d $repo_dir;

    my @all_repos;

    opendir( my $dh, $repo_dir ) or return;
    foreach my $f ( readdir($dh) ) {

        next unless $f =~ m{\.repo\z};

        my $path = "${repo_dir}/$f";

        next unless -f $path;

        my $found = _read_yum_repo_file($path);
        next unless defined $found && scalar @$found;

        push @all_repos, @$found;
    }

    return \@all_repos;
}

sub _get_all_debian_repos {
    my $repo_dir = DEBIAN_REPOS_D;

    return unless -d $repo_dir;

    # init with the main repo file
    my @all_repos;
    my $main = _read_debian_repo_file('/etc/apt/sources.list');
    push @all_repos, @$main if ref $main && scalar @$main;

    opendir( my $dh, $repo_dir ) or return;
    foreach my $f ( readdir($dh) ) {

        next unless $f =~ m{\.list\z};

        my $path = "${repo_dir}/$f";

        next unless -f $path;

        my $found = _read_debian_repo_file($path);
        next unless defined $found && scalar @$found;

        push @all_repos, @$found;
    }

    return \@all_repos;
}

sub _read_yum_repo_file ($f) {

    my $content = eval { Cpanel::LoadFile::load_if_exists($f) };
    return unless defined $content && length $content;

    my @lines = split( qr{\n}, $content );

    my $repo_data = {};
    my @repos;

    my $check_last_repo = sub {
        return unless length $repo_data->{id};

        my $repo = {
            id      => $repo_data->{id},
            name    => $repo_data->{name}    // '',
            enabled => $repo_data->{enabled} // 1,    # assume enabled unless explicitely disabled
            file    => File::Basename::basename($f),
        };

        foreach my $k (qw{ baseurl mirrorlist }) {
            next unless defined $repo_data->{$k};
            $repo->{$k} = $repo_data->{$k};
        }

        push @repos, $repo;

        return 1;
    };

    foreach my $line (@lines) {

        next if $line =~ qr{^\s*\#};       # skip comments
        $line =~ s{\s*\#.+$}{};            # strip comments

        next unless length $line;

        if ( $line =~ qr{^\s*\[\s*(.+)\s*\]} ) {
            my $id = $1;

            $check_last_repo->();
            $repo_data = { id => $id };    # reset the repo

            next;
        }
        next unless defined $repo_data->{id};

        my ( $key, $value ) = split( '=', $line, 2 );

        _sanitize( \$key );
        _sanitize( \$value );

        next unless length $key;

        $repo_data->{$key} = $value;
    }

    $check_last_repo->();

    return \@repos;
}

sub _read_debian_repo_file ($f) {
    my $content = eval { Cpanel::LoadFile::load_if_exists($f) };
    return unless defined $content && length $content;

    my @lines = split( qr{\n}, $content );

    my @repos;

    my $basename = File::Basename::basename($f);

    #my ( $name ) = ( $basename =~ m{^(.+)\.list$} );

    foreach my $line (@lines) {

        next if $line =~ qr{^\s*\#};       # skip comments
        $line =~ s{\s*\#.+$}{};            # strip comments

        _sanitize( \$line );

        next unless length $line;

        next unless $line =~ qr{^deb\s};    # skip the deb-src repo

        if ( $line =~ qr{ \s (https?://\S+) \s+(.+)\s* $}xi ) {
            my ( $url,          $extra )      = ( $1, $2 );
            my ( $distribution, $components ) = split( qr/\s+/, $extra, 2 );

            push @repos, {
                distribution => $distribution,
                components   => $components // '',    # preserve a flat version
                url          => $url,
                file         => $basename,
            };

        }

    }

    return \@repos;
}

sub _sanitize ($ref_str) {
    return unless ref $ref_str && defined $$ref_str;

    $$ref_str =~ s{^\s+}{};
    $$ref_str =~ s{\s+$}{};

    return;
}

1;
