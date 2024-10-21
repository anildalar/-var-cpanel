package Cpanel::UpdateGatherer::Gatherer;

#                                      Copyright 2024 WebPros International, LLC
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited.

use Moo;

use Cwd                 ();
use Digest::SHA         ();
use File::Path          ();
use File::ReadBackwards ();
use File::Spec          ();
use JSON                ();
use LWP::UserAgent      ();
use Net::DNS            ();
use Time::Local         ();
use URI                 ();
use Try::Tiny;

use Cpanel::UpdateGatherer::Std;    # after Moo

# note: this code was introduced in 11.72 and is design to work with Perl 5.26+

# do not add 'use' statement for cPanel packages
#   add any new required packages to this list instead

use constant CPANEL_MODULES => qw[
  Cpanel::AccessIds::ReducedPrivileges
  Cpanel::AcctUtils::Domain
  Cpanel::Analytics::Config
  Cpanel::CachedCommand
  Cpanel::Config::Httpd::EA4
  Cpanel::Config::LoadCpConf
  Cpanel::Config::LoadDemoUsers
  Cpanel::Config::LoadUserDomains::Count
  Cpanel::Config::LoadWwwAcctConf
  Cpanel::Config::userdata::TwoFactorAuth::Secrets
  Cpanel::Cpu
  Cpanel::DiskLib
  Cpanel::DNSLib::PeerStatus
  Cpanel::DnsUtils::Config
  Cpanel::DNSLib::PeerConfig
  Cpanel::FileUtils::Copy
  Cpanel::FileUtils::Link
  Cpanel::FileUtils::Move
  Cpanel::FindBin
  Cpanel::GreyList::Client
  Cpanel::GreyList::Config
  Cpanel::Hostname
  Cpanel::IPv6::Utils
  Cpanel::JSON
  Cpanel::LoadFile
  Cpanel::MysqlUtils::Connect
  Cpanel::MysqlUtils::Command
  Cpanel::MysqlUtils::MyCnf::Basic
  Cpanel::MysqlUtils::RemoteMySQL::ProfileManager
  Cpanel::Postgres::Connect
  Cpanel::PostgresUtils
  Cpanel::PublicSuffix
  Cpanel::PwCache
  Cpanel::PwCache::Build
  Cpanel::Reseller
  Cpanel::SafeDir::MK
  Cpanel::SafeRun::Dynamic
  Cpanel::SafeRun::Errors
  Cpanel::SafeRun::Object
  Cpanel::SafeRun::Simple
  Cpanel::Security::Authn::TwoFactorAuth
  Cpanel::Server::Type
  Cpanel::Sys::Hardware::Memory
  Cpanel::Validate::IP::Expand
  Cpanel::Validate::Username
  Cpanel::Validate::Username::Core
  Cpanel::YAML::Syck
  Whostmgr::Accounts::List
  Whostmgr::Resellers::Check
];

use constant ELEVATE_STAGE_FILE          => '/var/cpanel/elevate';
use constant ELEVATE_MANUAL_BLOCKER_FILE => '/var/cpanel/elevate-blockers';
use constant ELEVATE_SECADV_BLOCKER_FILE => '/var/cpanel/elevate-blockers.security-advisor';
use constant ELEVATE_NOC_TOUCH_FILE      => '/var/cpanel/elevate-noc-recommendations';

=head1 MODULE

C<Cpanel::UpdateGatherer::Gatherer>

=head1 DESCRIPTION

C<Cpanel::UpdateGatherer::Gatherer> provides tools for gathering server analytics.

=head1 SYNOPSIS

  my $gatherer;
  if ( eval { require Cpanel::UpdateGatherer::Gatherer } ) {
      $gatherer = Cpanel::UpdateGatherer::Gatherer->new( { 'update_log_file' => '/logs/update', } );

      $gatherer->compile();
      $gatherer->send_tarball();
      $gatherer->cleanup();
  }

=head2 PROPERTIES

=cut

#
# Add/Plug your custom gather method here
#   or use your isolated package used by add_modules_data
#
use constant COMMON_GATHERERS => qw{
  _add_mainip_to_meta_data
  _add_mainip_to_meta_data
  _add_result_duration_versions_to_meta_data
  _add_mycnf_userstats_to_meta_data
  _add_server_profile_to_meta_data
  _add_reseller_info_to_meta_data
  _add_ipv6_info_to_meta_data
  _add_cpaddons_to_meta_data
  _add_postgresql_to_meta_data
  _add_greylisting_stats_to_meta_data
  _add_remote_mysql_to_meta_data
  _add_theme_stat_to_meta_data
  _add_libcurl_version_to_meta_data
  _add_sysinfo_to_meta_data
  _add_install_log_to_meta_data
  _add_install_stats
  _add_mysql_old_password_info_to_meta_data
  _add_two_factor_authentication_info_to_meta_data
  _add_access_hash_info_to_meta_data
  _add_ea_info_to_meta_data
  _add_container_metrics_to_metadata
  _add_cpanel_plugins_info_to_meta_data
  _add_imunify_info_to_metadata
  _add_nameserver_details_to_meta_data
  _add_api_token_details_to_meta_data
  _add_passenger_details_to_meta_data
  _add_mx_type_and_dmarc_to_meta_data
  _add_metrics_by_domain
  _get_mail_disk_usage
  _add_backups_details_to_meta_data
  _add_hulk_config
  _add_allowstupidstuff_metadata
  _add_mysql_dbstats_to_metadata
  _add_hostname_resolution_to_metadata
  _add_service_sslinfo_to_metadata
  _add_default_nameservers_to_metadata
  _add_system_config_at_install_to_metadata
  _add_tcpwrappers_usage_to_meta_data
  _add_license_id_to_metadata
  _add_license_info_to_metadata
  _add_calendar_and_email_logins_to_metadata
  _add_db_versions_to_metadata
  _add_account_migration_info_to_metadata
  _add_retro_style_to_meta_data

  add_modules_data

  _add_number_of_distributed_accounts_to_meta_data
  _add_number_of_child_accounts_to_meta_data
  _add_demo_users_to_meta_data
  _add_elevate_to_meta_data
  _add_elevate_check_to_meta_data
  _add_team_info_to_meta_data
  _add_alternate_counts_to_meta_data
  _add_trueuser_metadata
  _cpanel_features

  _add_sysinfo_config_to_meta_data
  _add_envtype_to_meta_data

  _add_cpanel_config_to_meta_data
  _add_cpupdate_conf_to_meta_data
  _add_cpsources_conf_to_meta_data
  _add_rpm_local_version_to_meta_data
  _add_clustering_metrics_to_meta_data
  _add_modsecurity2_rule_to_meta_data
  _add_number_of_accounts_with_quota_set_to_metadata
  _add_number_of_accounts_with_bandwidth_cap_set_to_metadata
  _add_autossl_provider_to_meta_data

  _check_srs_enabled
  _add_exim_conf_local_data
  _add_sitejet_metrics
  _add_sqm_metrics
  _add_wwwacct_conf
  _add_domains_per_account
};

use constant RESTRICTED_GATHERERS => qw{
  _add_access_hash_usage_to_meta_data
};

has 'formatted_timestamp' => (
    is      => 'ro',
    lazy    => 1,
    builder => '_format_timestamp',
);

has 'tarball_destination_host' => (
    is      => 'ro',
    default => 'updatelogdrop.cpanel.net',
);

has 'tarball_destination_url' => (
    is      => 'ro',
    default => '/cgi-bin/upload',
);

has 'timestamp' => (
    is      => 'rw',
    default => time,
);

has 'update_analysis_dir' => (
    is      => 'ro',
    default => '/usr/local/cpanel/logs/update_analysis',
);

has 'update_log_dir' => (
    is      => 'ro',
    default => '/var/cpanel/updatelogs',
);

has 'cache_dir' => (
    is      => 'ro',
    default => '/var/cpanel/caches',
);

# we cannot build the logfile name using the timestamp,
#  as the timestamp can be different from the one used in the logfilename
has 'update_log_file' => (
    is => 'ro',
);

has 'version_after' => (
    is      => 'ro',
    lazy    => 1,
    builder => '_fetch_version',
);

has 'version_before' => (
    is      => 'rw',
    default => undef,
);

has 'legacy_cp_for_update_gatherer' => (
    is      => 'ro',
    lazy    => 1,
    builder => '_is_legacy_cp_for_update_gatherer',
);

has 'modules_dir' => (
    is      => 'ro',
    default => '/var/cpanel/perl/Cpanel/UpdateGatherer/modules',
);

has 'namespace' => (
    is      => 'ro',
    default => 'Cpanel::UpdateGatherer::modules',
);

has 'server_analytics_enabled' => (
    is      => 'ro',
    lazy    => 1,
    default => sub { return -e Cpanel::Analytics::Config::FEATURE_TOGGLES_DIR() . '/analytics_ui_includes' ? 1 : 0 },
);

has 'metadata' => (
    is      => 'ro',
    default => sub { return {} },
);

has 'cpconf' => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        return Cpanel::Config::LoadCpConf::loadcpconf() // {};
    },
);

=head2 FUNCTIONS

=cut

sub BUILD ( $self, $args ) {

    $self->_load_cpanel_modules();

    return $self;
}

sub _load_cpanel_modules ($self) {

    # do our best to load most of the cPanel packages
    foreach my $pm (CPANEL_MODULES) {
        $self->_load_module($pm)
          or warn("Fail to load module $pm\n");
    }

    return;
}

sub _load_module ( $self, $module ) {

    return unless defined $module && $module =~ qr{^[A-Za-z0-9_:]+$};

    eval qq{ require $module; 1 }
      or do {
        return;
      };

    return 1;
}

sub _format_timestamp ($self) {

    my ( $s, $m, $h, $d, $M, $y ) = gmtime $self->timestamp();
    ++$M;
    $y += 1900;
    map { $$_ = "0$$_" if $$_ < 10 } ( \$s, \$m, \$h, \$d, \$M );

    my $ts = "$y-$M-${d}T$h:$m:${s}Z";
    return $ts;
}

sub _working_dir ($self) {
    return join '/', $self->update_analysis_dir(), $self->formatted_timestamp();
}

sub _tarball ($self) {
    my $safe_name = $self->_working_dir();

    my @parts = split /\//, $safe_name;
    my $name  = pop @parts;
    return "$name.tar.gz";
}

# Creates the directory that all the tarballs/working dirs will live in
sub _create_analysis_dir ($self) {

    if ( !-d $self->update_analysis_dir() ) {
        if ( -e $self->update_analysis_dir() ) {
            return;
        }

        if ( !Cpanel::SafeDir::MK::safemkdir( $self->update_analysis_dir(), 0700 ) ) {
            return;
        }
    }
    elsif ( ( ( stat(_) )[2] & 0777 ) != 0700 ) {
        chmod 0700, $self->update_analysis_dir();
    }

    return 1;
}

sub _create_working_dir ($self) {

    return if !$self->_create_analysis_dir();

    my $working_dir = $self->_working_dir();

    if ( !-d $working_dir ) {
        if ( -e $working_dir ) {
            return;
        }

        if ( !Cpanel::SafeDir::MK::safemkdir( $working_dir, 0700 ) ) {
            return;
        }
    }
    elsif ( ( ( stat(_) )[2] & 0777 ) != 0700 ) {
        chmod 0700, $working_dir;
    }

    return 1;
}

sub _write_file ( $self, $filename, $lines_ref ) {

    my $fh;

    if ( !open $fh, '>', $filename ) {
        return;
    }

    print {$fh} @$lines_ref;
    close $fh;
    return 1;
}

sub _fetch_version ($self) {

    my $filename = '/usr/local/cpanel/version';
    my $version  = eval { Cpanel::LoadFile::loadfile($filename) } // '';
    chomp $version;

    return $version;
}

sub _add_clustering_metrics_to_meta_data ( $self, $meta ) {

    my @stand_peers = Cpanel::DNSLib::PeerConfig::getdnspeerlist( ['standalone'] );
    my @wo_peers    = Cpanel::DNSLib::PeerConfig::getdnspeerlist( ['write-only'] );
    my @sync_peers  = Cpanel::DNSLib::PeerConfig::getdnspeerlist( ['sync'] );

    my %peer_info = (
        members           => scalar(@stand_peers) + scalar(@wo_peers) + scalar(@sync_peers),
        standalone        => scalar(@stand_peers),
        write_only        => scalar(@wo_peers),
        sync              => scalar(@sync_peers),
        reseller_clusters => 0,
    );

    my @users_with_clustering;
    opendir( my $dh, '/var/cpanel/cluster' ) or return $meta->{clustering} = \%peer_info;
    @users_with_clustering = grep { !m/^(\.|\.\.|root)$/ } readdir($dh);
    closedir($dh) or return $meta->{clustering} = \%peer_info;

    $peer_info{reseller_clusters} = scalar(@users_with_clustering);

    return $meta->{clustering} = \%peer_info;
}

sub _add_modsecurity2_rule_to_meta_data ( $self, $meta ) {

    my $modsec_user = Cpanel::LoadFile::loadfile("/etc/apache2/conf.d/modsec/modsec2.user.conf");
    my @rules       = map { !m/^\s*$/ && !m/^\s*#/ ? ($_) : () } split( /\n/, $modsec_user );
    $meta->{modsec2}{has_custom_rules} = @rules ? 1 : 0;

    $meta->{modsec2}{vendors} = {};    # would be autovivified but if there are none we want it to exist and be an empty hashref if there are no vendors

    my $modsec_cpanel = Cpanel::LoadFile::loadfile("/etc/apache2/conf.d/modsec/modsec2.cpanel.conf");
    return if !opendir my $dh, "/etc/apache2/conf.d/modsec_vendor_configs";

    for my $vendor ( readdir($dh) ) {
        next if $vendor eq "." || $vendor eq "..";
        $meta->{modsec2}{vendors}{$vendor} = $modsec_cpanel =~ m{^\s*Include "/etc/apache2/conf\.d/modsec_vendor_configs/\Q$vendor\E/}m ? 1 : 0;
    }
    closedir $dh;

    return 1;
}

sub _add_cpaddons_to_meta_data ( $self, $meta ) {

    my @users;
    my $cpconf = $self->cpconf;

    my %cpmeta = map { $_ => { 'count' => 0, 'available' => 0, 'up_to_date' => 0 } } qw{
      cPanel::CMS::PostNuke
      cPanel::Bulletin_Boards::phpBB3
      cPanel::CMS::Xoops
      cPanel::Blogs::WordPress
      cPanel::CMS::Mambo
      cPanel::Gallery::Coppermine
      cPanel::CMS::Soholaunch
      cPanel::CMS::E107
      cPanel::Chat::phpMyChat
      cPanel::CMS::Nucleus
      cPanel::Ecommerce::OSCommerce
      cPanel::Bulletin_Boards::YaBB
      cPanel::CMS::Geeklog
      cPanel::Support::cPSupport
      cPanel::Bulletin_Boards::phpBB
      cPanel::Ecommerce::AgoraCart
      cPanel::Guest_Books::Advanced_Guestbook
      cPanel::CMS::phpWiki
      cPanel::Blogs::B2Evolution
    };

    my $list = try {
        no warnings 'once';
        require "$cpconf->{'root'}/cpaddons/cPAddonsConf.pm";    ## no critic qw(RequireBarewordIncludes)

        # Return value is being captured and checked.
        return \%cPAddonsConf::inst;                             ## no critic (TryTiny::ProhibitExitingSubroutine)
    };

    if ( !$list ) {
        $meta->{'cpaddons'}{'available'} = 0;
        $meta->{'cpaddons'}{'addons'}    = \%cpmeta;
        return 1;
    }
    $meta->{'cpaddons'}{'available'} = 1;

    require Cpanel::Config::Users;
    @users = Cpanel::Config::Users::getcpusers();

    foreach my $user (@users) {
        my $homedir = Cpanel::PwCache::gethomedir($user);
        next if !$homedir || $user eq 'root';
        my $dir = "$homedir/.cpaddons";
        Cpanel::AccessIds::ReducedPrivileges::call_as_user(
            sub {
                if ( opendir( my $dh, $dir ) ) {
                    while ( my $file = readdir($dh) ) {
                        next unless -f "$dir/$file" && $file =~ /\.yaml$/;
                        my $data = try { YAML::Syck::LoadFile("$dir/$file"); };
                        next unless $data;

                        my $addon     = $data->{'addon'};
                        my $addon_ver = $data->{'version'};
                        my $avail_ver = $list->{$addon}{'version'};

                        $cpmeta{$addon}{'count'}++;
                        $cpmeta{$addon}{'up_to_date'}++ if $avail_ver && $addon_ver && $avail_ver eq $addon_ver;

                        # It's possible for a user to have installed an addon,
                        # and then have had the administrator remove it from the
                        # list of available choices.
                        $cpmeta{$addon}{'available'} = $avail_ver || $list->{$addon}{'VERSION'} ? 1 : 0;
                    }
                    closedir($dh);
                }
            },
            $user
        );
    }
    $meta->{'cpaddons'}{'addons'} = \%cpmeta;
    return 1;
}

sub _add_mycnf_userstats_to_meta_data ( $self, $meta ) {

    $meta->{'mysql'}{'userstat'} = 0;
    try {
        my $value = Cpanel::MysqlUtils::MyCnf::Basic::_getmydb_param( 'userstat', '/etc/my.cnf' );
        if ( $value && $value =~ m/^(1|on)$/i ) {
            $meta->{'mysql'}{'userstat'} = 1;
        }
    };

    return 1;
}

sub _add_server_profile_to_meta_data ( $self, $meta ) {

    my $result = __api1_execute( 'Cpanel' => 'get_current_profile' );

    return 0 if !$result || $result->get_error();

    my $server_profile = $result->get_data();

    $meta->{'server_profile'} = $server_profile->{'code'};

    my @enabled_roles = map { $_->{module} } @{ $server_profile->{enabled_roles} };

    for my $role_hr ( @{ $server_profile->{optional_roles} } ) {
        my $result = __api1_execute( 'Cpanel' => 'is_role_enabled', { role => $role_hr->{module} } );
        next if !$result || $result->get_error();

        if ( $result->get_data()->{enabled} ) {
            push @enabled_roles, $role_hr->{module};
        }
    }

    $meta->{'enabled_server_profile_roles'} = \@enabled_roles;

    $meta->{'analytics'}{'server_analytics_enabled'} = $self->server_analytics_enabled;

    return 1;
}

sub _add_number_of_distributed_accounts_to_meta_data ( $self, $meta ) {

    local $ENV{"REMOTE_USER"} = 'root';
    my $result = __api1_execute( 'Accounts' => 'listaccts' );

    return 0 if !$result || $result->get_error();

    my $accounts  = $result->get_data();
    my @workloads = ('Mail');

    for my $workload (@workloads) {
        my @dist_accts;
        for my $account (@$accounts) {
            next if !$account->{'child_nodes'};
            my @child_nodes = $account->{'child_nodes'}->@*;
            next if !@child_nodes;

            if ( grep { $_->{'workload'} eq $workload } @child_nodes ) {
                push @dist_accts, $account;
            }
        }

        $meta->{'accounts'}{ 'distributed_' . $workload } = 0 + @dist_accts;
    }

    return 1;
}

sub __api1_execute (@args) {

    eval {
        require Whostmgr::API::1::Utils::Execute;
        1;
    } or return;
    return unless my $execute = 'Whostmgr::API::1::Utils::Execute'->can('execute');

    return $execute->(@args);
}

sub _add_number_of_child_accounts_to_meta_data ( $self, $meta ) {

    eval {
        require Cpanel::LinkedNode::List;
        1;
    } or return;

    # introduced in v11.93.9901.492
    return unless 'Cpanel::LinkedNode::List'->can('list_user_workloads');

    my $user_workloads = Cpanel::LinkedNode::List::list_user_workloads();
    my @workloads      = ('Mail');

    for my $workload (@workloads) {
        my @child_accounts = grep { ( $_->{workload_type} // '' ) eq $workload } @{$user_workloads};

        $meta->{'accounts'}{ 'child_' . $workload } = 0 + @child_accounts;
    }

    return 1;
}

sub _add_team_info_to_meta_data ( $self, $meta ) {

    my $team_info = $self->_get_team_info();
    $meta->{'accounts'}{'team_owner'} = $team_info->{'team_owner_count'};
    $meta->{'accounts'}{'team_user'}  = $team_info->{'team_user_count'};
    $meta->{'accounts'}{'team_roles'} = $team_info->{'team_user_roles_count'};

    return 1;
}

sub _add_demo_users_to_meta_data ( $self, $meta ) {

    my $demousers = Cpanel::Config::LoadDemoUsers::load();

    $meta->{'accounts'}{'accounts_in_demo_mode'} = scalar @{$demousers};

    return 1;
}

sub _add_elevate_to_meta_data ( $self, $meta ) {

    return unless ref $meta;
    return unless -e ELEVATE_STAGE_FILE;
    my $data = eval { Cpanel::JSON::LoadFile(ELEVATE_STAGE_FILE) } // {};

    return unless scalar keys %$data;

    my $elevate_keys = [
        '_elevate_process',
        '_run_once',
        'cloudlinux_database_installed',
        'disabled_cpanel_services',
        'ea4',
        'elevate_version_finish',
        'elevate_version_start',
        'final_notifications',
        'mysql-version',
        'reinstall',
        'stage_number',
        'status',
        'yum',
    ];
    my $elevate_data = { map { $_ => undef } @$elevate_keys };
    $self->_find_keys_in_data( $elevate_data, $data );

    foreach my $k ( keys %$elevate_data ) {
        delete $elevate_data->{$k} unless defined $elevate_data->{$k};
    }
    $meta->{'elevate'} = $elevate_data;

    return 1;
}

sub _find_keys_in_data ( $self, $values, $data ) {
    if ( ref($data) eq 'ARRAY' ) {
        foreach my $a (@$data) {
            $self->_find_keys_in_data( $values, $a );
        }
    }
    elsif ( ref($data) eq 'HASH' ) {
        foreach my $k ( keys %$data ) {
            if ( exists $values->{$k} && !defined $values->{$k} ) {
                $values->{$k} = $data->{$k};
            }
            else {
                $self->_find_keys_in_data( $values, $data->{$k} );
            }
        }
    }

    return;
}

sub _add_elevate_check_to_meta_data ( $self, $meta ) {

    return unless ref $meta;

    my $data         = {};
    my $good_records = 0;
    $data->{'noc-blocker'} = 1 if -f ELEVATE_NOC_TOUCH_FILE;
    foreach my $blocker_file ( ELEVATE_MANUAL_BLOCKER_FILE, ELEVATE_SECADV_BLOCKER_FILE ) {
        next unless -e $blocker_file;

        my ( undef, undef, $key ) = File::Spec->splitpath($blocker_file);
        $key =~ s/^elevate-blockers\.?//;
        $key ||= 'manual';

        # Defer validity checking to the consumer of the data:
        $data->{$key}->{'mtime'} = ( stat _ )[9];
        $data->{$key}->{'ctime'} = ( stat _ )[10];

        my $from_json = eval { Cpanel::JSON::LoadFile($blocker_file) } // {};
        $data->{$key}->{'blockers'} = $from_json->{'blockers'} // [];
        $good_records++ unless $@;
    }

    if ( exists $data->{'noc-blocker'} || $good_records ) {
        $meta->{'elevate-check'} = $data;
        return 1;
    }
    return;
}

# yet another way of counting users and domains
sub _add_alternate_counts_to_meta_data ( $self, $meta ) {

    return unless ref $meta;

    $meta->{alternate_users_home_count} = eval { $self->_alternate_users_home_count() } // -1;
    $meta->{alternate_users_pwd_count}  = eval { $self->_alternate_users_pwd_count() }  // -1;

    $meta->{alternate_domains_httpd_count} = eval { $self->_alternate_domains_servername_count() } // -1;

    return 1;
}

sub _cpanel_features ( $self, $meta ) {

    my $r = Cpanel::SafeRun::Object->new(
        program => '/usr/local/cpanel/cpanel',
        args    => ['-F'],
    );
    $meta->{'features'} = $r->CHILD_ERROR ? 0 : 1;

    return 1;
}

sub _add_trueuser_metadata ( $self, $meta ) {

    return unless ref $meta;

    # Discrepancies here could be of interest if cross referenced by data in
    # $meta->{'domains_by_type'} defined over in _add_domains_per_account
    $meta->{'users'}->{'trueuserdomains'}      = Cpanel::Config::LoadUserDomains::Count::counttrueuserdomains();
    $meta->{'users'}->{'userdomains'}          = Cpanel::Config::LoadUserDomains::Count::countuserdomains();

    $meta->{'users'}->{'domainless_resellers'} = 0;
    $meta->{'users'}->{'domainless_cpanel'}    = 0;
    $meta->{'users'}->{'with_domain'}          = 0;
    $meta->{'users'}->{'cptkt'}                = 0;
    $meta->{'users'}->{'reserved'}             = 0;
    $meta->{'users'}->{'vcu_total'}            = 0;
    $meta->{'users'}->{'vcu_unreserved'}       = 0;
    $meta->{'users'}->{'vcu_unknown'}          = 0;

    my $users_dir = q[/var/cpanel/users];

    my %users_from_pwcache;
    my $pwcache_ok = eval { Cpanel::PwCache::Build::init_passwdless_pwcache(); 1 };
    if ($pwcache_ok) {
        %users_from_pwcache = map { ( $_->[0] => 1 ) } @{ Cpanel::PwCache::Build::fetch_pwcache() };
        foreach my $user ( keys %users_from_pwcache ) {
            next unless length $user && -e "$users_dir/$user";

            if ( index( $user, 'cptkt' ) == 0 ) {
                $meta->{'users'}->{'cptkt'}++;
                next;
            }

            if ( Cpanel::Validate::Username::Core::reserved_username_check($user) ) {
                $meta->{'users'}->{'reserved'}++;
                next;
            }

            my $domain = Cpanel::AcctUtils::Domain::getdomain($user);
            if ( length $domain ) {
                $meta->{'users'}->{'with_domain'}++;
            }
            elsif ( Whostmgr::Resellers::Check::is_reseller($user) ) {
                $meta->{'users'}->{'domainless_resellers'}++;
            }
            else {
                $meta->{'users'}->{'domainless_cpanel'}++;
            }
        }
    }

    if ( opendir( my $dh, $users_dir ) ) {
        foreach my $user ( readdir($dh) ) {
            next if $user =~ qr{^\.};
            my $path = "$users_dir/$user";

            next unless -f $path;

            $meta->{'users'}->{'vcu_total'}++;

            next if Cpanel::Validate::Username::Core::reserved_username_check($user);

            $meta->{'users'}->{'vcu_unreserved'}++;

            if ( !defined $users_from_pwcache{$user} ) {
                $meta->{'users'}->{'vcu_unknown'}++;
            }
        }
    }

    return 1;
}

# provide a non opiniated and naive way of counting users

sub _users_to_skip() {

    my @exceptions = qw{
      _imunify
      centos
      chrony
      cloud-user
      cpanel
      cpanelanalytics
      cpanelcabcache
      cpanelconnecttrack
      cpaneleximfilter
      cpaneleximscanner
      cPanelInstall
      cpanellogin
      cpanelphpmyadmin
      cpanelphppgadmin
      cpanelroundcube
      cpses
      dovenull
      mailman
      nfsnobody
      nobody
      polkitd
      redis
      ubuntu
      virtfs
    };
    return \@exceptions;
}

sub _alternate_users_pwd_count ($self) {

    my $min_uid = eval { require Cpanel::OS; Cpanel::OS::default_uid_min() } // 500;

    my $exceptions = _users_to_skip();
    my $count      = 0;

    open( my $fh, '<', q[/etc/passwd] ) or die $!;
    while ( my $line = readline $fh ) {
        next if $line =~ m{^\s*\#};
        my ( $user, $x, $uid ) = split( ':', $line );
        next unless defined $user && $uid;
        next if $uid <= $min_uid;
        next if grep { $_ eq $user } @$exceptions;
        ++$count;
    }

    return $count;
}

sub _alternate_users_home_count ($self) {

    my $home = $self->_default_useradd()->{HOME} // '/home';
    return 0 unless -d $home;

    my $exceptions = _users_to_skip();

    my $count = 0;

    opendir( my $dh, $home ) or die "Cannot open /home directory: $!";
    foreach my $d ( readdir($dh) ) {
        next if $d =~ qr{^\.};
        my $path = "$home/$d";
        next unless -d $path;
        next if grep { $_ eq $d } @$exceptions;
        ++$count;
    }

    return $count;
}

sub _alternate_domains_servername_count ($self) {

    my $httpd_conf;
    {
        require Cpanel::ConfigFiles::Apache;
        open( my $fh, '<', Cpanel::ConfigFiles::Apache::apache_paths_facade()->file_conf() )
          or return;
        $httpd_conf = do { local $/; <$fh> };
    }

    return unless length $httpd_conf;

    # Cpanel::ApacheConf::Parser::Regex::VirtualHost_ServerName_Capture();
    my $ServerName_Capture = qr/^[\s]*servername[ \t]+(?:www\.)?(\S+)/is;

    my %domains;

    my @lines = split( "\n", $httpd_conf );
    foreach my $line (@lines) {
        next unless $line =~ $ServerName_Capture;
        my $domain = lc $1;
        next if $domain =~ qr{\.localhost};
        $domains{$domain} = 1;
    }

    my $valuable_domains = 0;

    my @all_domains = sort { length $a <=> length $b } keys %domains;
    foreach my $d (@all_domains) {

        my $is_uniq = 1;

        my @parts = split( /\./, $d );
        shift @parts;
        while ( scalar @parts >= 2 ) {
            my $c = join( '.', @parts );
            if ( $domains{$c} ) {
                $is_uniq = 0;
                last;
            }
            shift @parts;
        }
        next unless $is_uniq;

        ++$valuable_domains;

    }

    return $valuable_domains;
}

sub _default_useradd ($self) {

    my $f = q[/etc/default/useradd];
    return {} unless -e $f;

    my $data = {};
    if ( open my $fh, '<', $f ) {
        while ( my $line = readline $fh ) {
            next if $line =~ m{^\s*\#};
            if ( $line =~ qr{^ \s* (\S+) \s* = \s* (\S+) }xms ) {
                $data->{$1} = $2;
            }
        }
    }

    return $data;
}

sub _add_reseller_info_to_meta_data ( $self, $meta, $reseller_path = undef, $accounting_path = undef ) {

    $reseller_path   //= '/var/cpanel/resellers';
    $accounting_path //= '/var/cpanel/accounting.log';

    require Whostmgr::ACLS;
    Whostmgr::ACLS::init_acls();
    $meta->{'reselleracls'} = \%Whostmgr::ACLS::default;
    if ( open( my $res_fh, '<', $reseller_path ) ) {
        while (<$res_fh>) {
            chomp;
            my ( undef, $list ) = split( /:/, $_, 2 );
            next unless defined $list;

            my @acls = split( /\,/, $list );
            foreach my $acl (@acls) {
                $meta->{'reselleracls'}{$acl}++;
            }
        }
        close($res_fh);
    }

    if ( open( my $accounting_fh, '<', $accounting_path ) ) {
        $meta->{'reseller_without_domain'} = { total_created => 0 };
        while (<$accounting_fh>) {
            chomp;
            if (s/:CREATERESELLERWITHOUTDOMAIN:.*//) {    # don't split on colon; timestamp also has colons
                my ($year) = m/ ([0-9]{4})$/;
                $year ||= '';
                $meta->{'reseller_without_domain'}{$year}++;
                $meta->{'reseller_without_domain'}{total_created}++;
            }
        }
        close($accounting_fh);
    }

    return 1;
}

sub _add_ipv6_info_to_meta_data ( $self, $meta ) {

    my $ipv6 = $meta->{'ipv6'} //= {};

    #
    # First question:
    # Find out if they have any IPv6 ranges enabled
    #

    # We'll start with 'no' until proven otherwise
    $ipv6->{'has_ipv6_address_range'} = 0;

    # Load the range file; if we can't, then there are no ranges
    my ( $ret, $range_data_ref ) = Cpanel::IPv6::Utils::load_range_config();
    if ( $ret and ref $range_data_ref eq 'HASH' ) {

        # Search the range data hashref for enabled ranges
        my @ranges = grep { $range_data_ref->{$_}{'enabled'} } keys %{$range_data_ref};

        # Set flag if there is at least one enabled range
        $ipv6->{'has_ipv6_address_range'} = scalar @ranges ? 1 : 0;
    }

    #
    # Second question:
    # How many IPv6 addresses do they have bound?
    #

    # First get the bound ip addresses
    my $addrs_ref = Cpanel::IPv6::Utils::get_bound_ipv6_addresses();

    # The data return by get_bound_ipv6_addresses is a hash of hashes of hashes
    # containing an element for the actuall address
    # Transform this hash of hashes of hashes into a simple array of addresses
    # We'll also have use for this array of addresses later
    my @bound_addresses = map { $_->{'ip'} } map { values %{$_} } values %{$addrs_ref};

    # Now we can set how many bound addresses
    $ipv6->{'bound_address_count'} = scalar @bound_addresses;

    #
    # Third question:
    # How many users are on the system as a whole
    #

    # Since we are running as a script, well have to fake out the hasroot function
    # hasroot is called within the _listaccts() function
    no warnings 'redefine';
    local *Whostmgr::ACLS::hasroot = sub { 1 };    # PPI NO PARSE: no need to load Whostmgr::ACLS

    # Get the account data
    my $account_array_ref = Whostmgr::Accounts::List::listaccts();

    # Set the number of accounts with ipv6
    $ipv6->{'accounts_with_ipv6'} =
      scalar grep { $_->{'ipv6'} and scalar @{ $_->{'ipv6'} } } @{$account_array_ref};

    # Set the number of accounts with jailshell
    # NOTE: we're already loading all the accounts here, there's no reason to recompute this elsewhere #
    $ipv6->{'accounts_with_jailshell'} =
      scalar grep { $_->{'shell'} eq '/usr/local/cpanel/bin/jailshell' } @{$account_array_ref};

    #
    # Fourth question:
    # Do they have a SLAAC address
    #
    my @slaac_addresses = _find_slaac_addresses(@bound_addresses);

    # print "SLAAC Addresses:  @slaac_addresses\n";

    $ipv6->{'has_slaac'} = scalar @slaac_addresses ? 1 : 0;

    # See if any of the slaac addresses are the host address
    my $host_ipv6   = eval { _get_host_ipv6_address() };
    my @host_slaacs = $host_ipv6 ? ( grep { $host_ipv6 eq $_ } @slaac_addresses ) : ();

    $ipv6->{'host_is_slaac'} = scalar @host_slaacs ? 1 : 0;

    #
    # Fifth question:
    # Do they have any A6 records
    #

    # Lets find out
    my $zone_dir = Cpanel::DnsUtils::Config::find_zonedir();
    my @a6_lines;
    @a6_lines = `/bin/egrep "IN[[:space:]]+A6[[:space:]]+" $zone_dir/* 2> /dev/null` if length $zone_dir;

    $ipv6->{'num_a6_records'} = scalar @a6_lines;

    #
    # New question:
    # What network interfaces do they have?
    #

    # Get the network interfaces
    my $net_intf_hash = _get_network_interfaces();
    $ipv6->{'network_interfaces'} = $net_intf_hash;

    # Last, return
    return 1;
}

#
# Get the host's ipv6 address, we want to see what DNS is pointing to
#
sub _get_host_ipv6_address() {

    my $hostname = Cpanel::Hostname::gethostname();

    # Get the ipv6 address that is mapped to this host
    return eval { _get_ipv6_address_for_hostname($hostname) };
}

#
# Query DNS to get the IPv6 address for a specific host
#
sub _get_ipv6_address_for_hostname ($hostname) {

    my $res = Net::DNS::Resolver->new();
    my $ret = $res->send( $hostname, "AAAA", "IN" ) or return;
    my @ans = $ret->answer;

    # The answer can contain items other than the AAAA record we requested
    @ans = grep { ref $_ eq "Net::DNS::RR::AAAA" } @ans;

    return unless scalar @ans;

    # The rest of the code will expect the address to be in compressed format
    my $address = eval { $ans[0]->address } or return;
    $address = Cpanel::Validate::IP::Expand::normalize_ipv6($address) if $address;

    return $address;
}

#
# Given a list of IPv6 addresses, return the ones which are slaac addresses
#
sub _find_slaac_addresses (@addresses) {

    my @mac_addresses = _get_mac_addresses();

    # Convert the mac addresses to ipv6 suffixes and compact them
    # Since our list of ipv6 addresses will be in compacted format
    my @ipv6_suffixes =
      map { substr( Cpanel::Validate::IP::Expand::normalize_ipv6("::$_"), 2 ) }
      map { _convert_mac_to_ipv6_suffix($_) } @mac_addresses;

    # Find which ipv6 addresses have any of the converted mac addresses as suffixes
    my @results;
    foreach my $address (@addresses) {
        foreach my $suffix (@ipv6_suffixes) {
            push @results, $address if ( $address =~ /$suffix$/ );
        }
    }

    return @results;
}

#
# Get all the MAC addresses
#
sub _get_mac_addresses() {

    # Invoke ip to get all the interfaces with their MAC addresses
    my @output = Cpanel::SafeRun::Errors::saferunnoerror( '/sbin/ip', '-o', 'link', 'show' );

    # Get rid of the loopback interface(s)
    @output = grep { $_ !~ /loopback/ } @output;

    # Strip out the MAC address from this
    @output = grep { $_ } map { /link\/\w+\s+([a-fA-F\d:]+)/; $1 } @output;

    return @output;
}

#
# Get all the network interfaces
#
sub _get_network_interfaces() {

    # Invoke ip to get all the interfaces
    my @output = Cpanel::SafeRun::Errors::saferunnoerror( '/sbin/ip', '-o', 'link', 'show' );

    # Strip out the interface name & type from the output
    my $results_hr = {};
    foreach my $line (@output) {

        # Grab the interface name from the line of output
        # If there is no interface name, then skip this line
        next unless ( $line =~ /^\s*\d+:\s+([^:]+):/ );
        my $name = $1;

        # Next strip out the interface type (if present)
        my $type = ( $line =~ /link\/(\w+)/ ) ? $1 : '';

        $results_hr->{$name} = $type;
    }

    return $results_hr;
}

#
# Take a MAC address & convert it to the last 64 bits of an IPv6 SLAAC address
#
sub _convert_mac_to_ipv6_suffix ($mac) {

    # A MAC address has exactly 6 bytes (as hex) separated by colons or dashes
    my @chunks = map { hex $_ } split( /[-:]/, $mac );
    return if ( scalar @chunks != 6 );

    # Make this into an eui64 by inserting magic value 0xfffe into the middle
    @chunks = ( @chunks[ 0 .. 2 ], 0xff, 0xfe, @chunks[ 3 .. 5 ] );

    # Invert the Universal/Local flag in the first byte of the address
    $chunks[0] ^= 2;

    # Combine adjacent bytes & turn back into a string
    return join(
        ':',
        map {
            my $i = $_;
            $i *= 2;
            sprintf( '%02x%02x', $chunks[$i], $chunks[ $i + 1 ] )
        } 0 .. 3
    );
}

sub _add_result_duration_versions_to_meta_data ( $self, $meta ) {

    my $result = 0;
    my ( @first_localtime, @last_localtime, @detected_versions );

    if ( !$self->update_log_file() ) {
        if ( !$self->legacy_cp_for_update_gatherer ) {
            $meta->{'version'} = {
                'before' => undef,
                'after'  => $self->_fetch_version(),
            };
        }

        return 0;
    }

    if ( open my $fh, '<', $self->update_log_file() ) {
        while ( my $line = readline $fh ) {
            if ( $line =~ m/^\[([0-9]{4})\-([0-9]{2})\-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) [+\-]?\d+\]/ ) {
                if ( !scalar(@first_localtime) ) {

                    # $6 = seconds
                    # $5 = minutes
                    # $4 = hours
                    # $3 = day of month
                    # $2 = month (localtime: month in the range 0..11, so we subtract 1)
                    # $1 = year
                    @first_localtime = ( $6, $5, $4, $3, $2 - 1, $1 );
                }
                else {
                    @last_localtime = ( $6, $5, $4, $3, $2 - 1, $1 );
                }

                if ( $line =~ m/Completed all updates/ ) {
                    $result = 1;
                    last;
                }
            }
            if ( $line =~ m/Detected version '((?:\d+\.){3}\d+)'/ ) {
                push @detected_versions, $1;
            }
        }

        close $fh;
    }

    my $duration = 0;

    if ( scalar(@first_localtime) && scalar(@last_localtime) ) {
        my $start_time = Time::Local::timelocal(@first_localtime);
        my $end_time   = Time::Local::timelocal(@last_localtime);
        $duration = $end_time - $start_time;
    }

    $meta->{'result'}   = $result;
    $meta->{'duration'} = $duration;
    if ( !$self->legacy_cp_for_update_gatherer ) {
        $meta->{'version'} = {
            'before' => $detected_versions[0],
            'after'  => $detected_versions[-1] // $self->_fetch_version(),
        };
    }

    return 1;
}

sub _add_postgresql_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    # default values when unused
    $meta->{'postgresql'} = { 'installed' => 0 };

    if ( Cpanel::PostgresUtils::find_psql() && Cpanel::PostgresUtils::find_pgsql_data() ) {

        # consider that posgresql is installed
        $meta->{'postgresql'}->{'installed'} = 1;
    }

    return 1;
}

sub _add_greylisting_stats_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $greylisting_meta = { 'is_enabled' => 0, 'trusted_hosts' => {} };
    my ( $triplets_deferred_count, $possible_spam_count, $number_of_domains_opted_out, $total_number_of_domains ) = ( 0, 0, 0, 0 );
    try {
        $total_number_of_domains = Cpanel::SafeRun::Errors::saferunnoerror( '/usr/bin/wc', '-l', '/etc/userdatadomains' );
        chomp $total_number_of_domains;

        $greylisting_meta->{'is_enabled'} = Cpanel::GreyList::Config::is_enabled() ? 1 : 0;
        if ( $greylisting_meta->{'is_enabled'} ) {
            $greylisting_meta->{'conf'} = Cpanel::GreyList::Config::loadconfig();

            my @stats = Cpanel::SafeRun::Errors::saferunnoerror( '/usr/local/cpanel/3rdparty/bin/sqlite3', '/var/cpanel/greylist/greylist.sqlite', 'select * from stats; select count(*) from opt_out_domains;' );
            chomp @stats;

            ( undef, $triplets_deferred_count, $possible_spam_count ) = split( /\|/, $stats[0], 3 );
            $number_of_domains_opted_out = $stats[1];

            $greylisting_meta->{'trusted_hosts'} = Cpanel::GreyList::Client->new()->read_trusted_hosts();
        }
    };

    $greylisting_meta->{'stats'} = {
        'triplets_deferred_count'           => $triplets_deferred_count,
        'possible_spam_count'               => $possible_spam_count,
        'number_of_domains_opted_out'       => $number_of_domains_opted_out,
        'total_number_of_domains_on_server' => $total_number_of_domains,
    };

    $meta->{'greylisting'} = $greylisting_meta;

    return 1;
}

sub _add_remote_mysql_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $remote_mysql_meta = { 'is_local' => 0, 'address' => "", 'setup_with_ssh' => 0 };
    try {
        my $profile_manager        = Cpanel::MysqlUtils::RemoteMySQL::ProfileManager->new( { 'read_only' => 1 } );
        my $active_profile         = $profile_manager->get_active_profile();
        my $active_profile_details = $profile_manager->read_profiles()->{$active_profile};

        # Is the active profile Remote or local?
        $remote_mysql_meta->{'is_local'} = ( Cpanel::MysqlUtils::MyCnf::Basic::is_local_mysql( $active_profile_details->{'mysql_host'} ) ) ? 1 : 0;

        # Get the address of the profile
        $remote_mysql_meta->{'address'} = $active_profile_details->{'mysql_host'} . ":" . $active_profile_details->{'mysql_port'};

        # Profile was setup using SSH or manual credentials?
        $remote_mysql_meta->{'setup_with_ssh'} = ( $active_profile_details->{'setup_via'} =~ /ssh/i ) ? 1 : 0;
    };

    $meta->{'remotemysql'} = $remote_mysql_meta;

    return 1;
}

sub _add_two_factor_authentication_info_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $tfa_meta = {
        'is_enabled_on_server'               => 0,
        'is_root_configured'                 => 0,
        'total_accounts_with_tfa_configured' => 0,
    };

    try {
        $tfa_meta->{'is_enabled_on_server'} = Cpanel::Security::Authn::TwoFactorAuth::is_enabled();

        my $tfa_userdata = Cpanel::Config::userdata::TwoFactorAuth::Secrets->new( { 'read_only' => 1 } )->read_userdata();

        $tfa_meta->{'total_accounts_with_tfa_configured'} = scalar keys %{$tfa_userdata};
        $tfa_meta->{'is_root_configured'}                 = ( exists $tfa_userdata->{'root'} ) ? 1 : 0;
    };

    $meta->{'twofactorauth'} = $tfa_meta;

    return 1;
}

sub _add_access_hash_info_to_meta_data ( $self, $meta ) {

    $meta->{'accesshash'}{'cluster_members'} = _find_access_hash_in_dns_cluster_config();
    $meta->{'accesshash'}{'potential_users'} = _count_resellers_with_access_hash();

    return 1;
}

# This one is gated by the UI Analytics toggle.
sub _add_access_hash_usage_to_meta_data ( $self, $meta ) {

    my $threshold = 90 * 24 * 60 * 60;    # 90 days

    $meta->{'accesshash'}{'recent_use'} = _scan_access_log_for_access_hash_use( '/usr/local/cpanel/logs/access_log', $threshold );

    return 1;
}

sub _scan_access_log_for_access_hash_use ( $log, $threshold ) {

    my $now = time;

    my $access_log = File::ReadBackwards->new($log);
    if ( !$access_log ) {
        return;
    }

    my %counts;
    while ( defined( my $entry = $access_log->readline ) ) {
        chomp $entry;

        #use re 'debugcolor';
        next if $entry !~ m@

            # combined log format fields:
            ^
            (?:\S+) [ ]         # client (unused)
            (?:\S+) [ ]         # identd check (unused)
            (?:\S+) [ ]         # username (unused)
            \[([^\]]+)\] [ ]    # timestamp ($1)
            "(?:GET|POST) [ ] (.*?) (?: [ ] HTTP/[0-9.]+)?" [ ]      # request verb (unused), URL ($2), protocol version (unused)
            ([0-9]{3}) [ ]      # response status ($3)
            (?:[0-9]+|-) [ ]    # response body size (unused)
            " (?:.*) " [ ]      # referer (unused)
            " (?:.*) " [ ]      # user agent (unused)

            # special fields added by cpsrvd:
            " ([a-z-]) " [ ]    # authentication type ($4)
            " (?:.*) " [ ]      # x-forwarded-for header (unused)
            ([0-9]+)            # server port ($5)
            $

        @xa;

        my ( $timestamp, $url, $status, $authtype, $serverport ) = ( $1, $2, $3, $4, $5 );

        # Why did we have to change the timestamp format? XD
        my ( $month, $mday, $year, $hour, $min, $sec ) = $timestamp =~ m'^(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) -0000$'a;
        next unless defined $year;    # skip if no match

        my $ts = eval { Time::Local::timegm_modern( $sec, $min, $hour, $mday, $month - 1, $year ) };

        # Above can blow up for various reasons. If that happens, move on and warn, but without spamming the log:
        if ( !$ts ) {
            next;
        }

        # If the request is older than the threshold interval, stop looking:
        last if $now - $ts > $threshold;

        # If the request doesn't use an accesshash or didn't return a 2xx status code, move on:
        next if $authtype ne 'a' || substr( $status, 0, 1 ) ne '2';

        my $usage_type = _divine_usage_from_url($url);
        $counts{$usage_type}++ if $usage_type;
    }

    $access_log->close();

    return \%counts;
}

sub _divine_usage_from_url ($url) {
    my @segments = URI->new( $url, 'https' )->canonical->path_segments;

    # If the path isn't absolute, something is wrong.
    my $seg = shift @segments;
    return 'other' if !defined $seg || $seg ne '';

    $seg = shift @segments;

    # Get rid of session / cache-busting fluff:
    $seg = shift @segments if defined $seg && $seg =~ m/^(?:cpsess|cPanel_magic_revision_)\d+$/a;

    return $seg || 'other';
}

# Should servers with cluster members configured but clustering disabled count? They currently do.
sub _find_access_hash_in_dns_cluster_config() {

    my %count = ( 'disabled' => 0, 'enabled' => 0 );

    return \%count unless 'Cpanel::DNSLib::PeerStatus'->can('getclusterstatus');

    # Get DNS Cluster information, namely how many cluster members are accessed with access hashes:
    my %dns_cluster_configs = Cpanel::DNSLib::PeerStatus::getclusterstatus();
    foreach my $member ( map { @$_ } @dns_cluster_configs{ 'standalone', 'write-only', 'sync' } ) {

        next unless defined $member->{'pass'} && length $member->{'pass'} >= 900;    # should be 960, but leaving room for a fudge factor

        if ( $member->{'disabled'} ) {
            $count{'disabled'}++;
        }
        else {
            $count{'enabled'}++;
        }
    }

    return \%count;
}

sub _count_resellers_with_access_hash() {

    my @resellers = _get_list_of_resellers();

    unshift @resellers, 'root';    # consider root to be a reseller

    return scalar grep { -f Cpanel::PwCache::gethomedir($_) . '/.accesshash' } @resellers;
}

sub _get_list_of_resellers {
    local $ENV{"REMOTE_USER"} = 'root';
    my $result = __api1_execute( 'Resellers' => 'listresellers' );
    if ($result) {
        my $error = $result->get_error();
        if ( !$error ) {
            return @{ $result->get_data };    # XXX get_data violates principle of least surprise by unpacking the array from its containing singleton hash
        }
    }
    return;
}

sub _add_mysql_old_password_info_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    $meta->{'mysql'}->{'old_passwords'}            = undef;
    $meta->{'mysql'}->{'users_with_old_passwords'} = 0;

    try {
        my $dbh = Cpanel::MysqlUtils::Connect::get_dbi_handle();
        if ( $dbh->{'mysql_serverversion'} < 50700 ) {

            # MySQL allows you to specify parameters with underscores or hyphens, so need to allow for both variants.
            my $value = Cpanel::MysqlUtils::MyCnf::Basic::_getmydb_param( 'old_passwords', '/etc/my.cnf' )
              || Cpanel::MysqlUtils::MyCnf::Basic::_getmydb_param( 'old-passwords', '/etc/my.cnf' );

            $meta->{'mysql'}->{'old_passwords'} = ( $value && $value =~ m/^(1|on)$/i ? 1 : 0 );

            my $count = Cpanel::MysqlUtils::Command::sqlcmd('SELECT count(*) FROM mysql.user WHERE CHAR_LENGTH(Password) <= 16;');
            $meta->{'mysql'}->{'users_with_old_passwords'} = $count ? $count : 0;
        }
    };

    return 1;
}

sub _add_theme_stat_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    $meta->{'theme'} = {};

    my $wwwacctconf_ref = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
    $meta->{'theme'}->{'default_theme'} = $wwwacctconf_ref->{'DEFMOD'};
    $meta->{'theme'}->{'x3'}            = 0;
    $meta->{'theme'}->{'x3mail'}        = 0;
    $meta->{'theme'}->{'paper_lantern'} = 0;
    $meta->{'theme'}->{'jupiter'}       = 0;

    # Since we are running as a script, well have to fake out the hasroot function
    # hasroot is called within the _listaccts() function
    no warnings 'redefine';
    local *Whostmgr::ACLS::hasroot = sub { 1 };    # PPI NO PARSE: no need to load Whostmgr::ACLS

    # Get the account data
    my $account_array_ref = Whostmgr::Accounts::List::listaccts();
    foreach my $u ( @{$account_array_ref} ) {
        my $user_theme = $u->{'theme'};
        next unless $user_theme;
        if ( $meta->{'theme'}->{$user_theme} ) {
            $meta->{'theme'}->{$user_theme}++;
        }
        else {
            $meta->{'theme'}->{$user_theme} = 1;
        }
    }

    $meta->{'theme'}->{'system_branding'} = -e '/var/cpanel/customizations/brand' ? 1 : 0;

    my $theme_cache_file = $self->cache_dir() . '/reseller_branding.cache';
    my @user_branding    = ();
    if ( -e $theme_cache_file && open( my $cache_fh, '<', $theme_cache_file ) ) {
        @user_branding = <$cache_fh>;
        close $cache_fh;
    }
    else {
        @user_branding = glob( $wwwacctconf_ref->{'HOMEDIR'} . '/*/var/cpanel/reseller/brand' );
        if ( open( my $cache_fh, '>', $theme_cache_file ) ) {
            print {$cache_fh} join( "\n", @user_branding );
            close $cache_fh;
        }
    }
    $meta->{'theme'}->{'reseller_branding'} = scalar @user_branding;

    return 1;
}

# Counts the number of users still on retro style. This could be the style chosen
# by the user, or the default set by the owner, either a reseller or the root.
sub _add_retro_style_to_meta_data ( $self, $meta ) {

    my $save_file = join '/', $self->update_analysis_dir(), 'retro_users.json';

    my $save_data = $self->_load_retro_data($save_file);
    if ( $save_data && defined $save_data->{'retro_users'} ) {
        $meta->{'retro_users'} = $save_data->{'retro_users'};
        return;
    }

    # Since we are running as a script, well have to fake out the hasroot function
    # hasroot is called within the _listaccts() function
    no warnings 'redefine';
    local *Whostmgr::ACLS::hasroot = sub { 1 };    # PPI NO PARSE: no need to load Whostmgr::ACLS
    use warnings 'redefine';

    # Get the account data
    my $account_array_ref = Whostmgr::Accounts::List::listaccts();

    # we are only concerned with retro style provided with the paper_lantern
    # theme from cpanel
    my $paper_lantern_users = [ grep { $_->{'theme'} eq 'paper_lantern' } @{$account_array_ref} ];

    my $retro_count = $self->_count_users_with_retro_style($paper_lantern_users);

    $meta->{'retro_users'}      = $retro_count;
    $save_data                  = {};
    $save_data->{'retro_users'} = $retro_count;

    # save the result so we don't have to run this every time.
    # no need to die if we can't save becaue we will get another chance
    # next time.
    $self->_create_analysis_dir();
    local $@;
    return eval { Cpanel::JSON::DumpFile( $save_file, $save_data ) };
}

sub _count_users_with_retro_style ( $self, $paper_lantern_users = undef ) {

    $paper_lantern_users //= [];

    # Cpanel::Styles was removed in v11.109.9999.63
    return 0 unless eval { require Cpanel::Styles; 1 };

    my $retro_count = 0;

    foreach my $user ( @{$paper_lantern_users} ) {
        local %Cpanel::CPDATA = (
            'OWNER' => $user->{'owner'},
            'RS'    => $user->{'theme'}
        );
        local $Cpanel::user = $user->{'user'};

        Cpanel::Reseller::getresellersaclhash();    # prime the memory cache for resellers
        local $Cpanel::isreseller = Cpanel::Reseller::isreseller( $user->{'user'} );

        local $Cpanel::homedir = Cpanel::PwCache::gethomedir( $user->{'user'} );

        # we are switching users each loop
        Cpanel::Styles::_clear_cache();

        my $user_style = Cpanel::Styles::get_current_style();
        $retro_count++ if $user_style && $user_style->{'name'} eq 'retro';
    }

    return $retro_count;
}

sub _load_retro_data ( $self, $file ) {

    return unless -e $file;

    # set the save file expiration to one week ( in seconds )
    my $mtime = ( stat($file) )[9];
    return if ( time() - $mtime ) > 604800;

    my $file_data;
    try {
        # we do not want to abort the process for bad data
        # if the data is bad, we just generate it
        $file_data = Cpanel::JSON::LoadFile($file);
    };

    return $file_data;
}

sub _add_sysinfo_to_meta_data ( $self, $meta ) {

    # provide memory information #
    $meta->{'mem_total'}     = Cpanel::Sys::Hardware::Memory::get_installed();
    $meta->{'mem_swap'}      = Cpanel::Sys::Hardware::Memory::get_swap();
    $meta->{'mem_available'} = Cpanel::Sys::Hardware::Memory::get_available();
    $meta->{'mem_used'}      = Cpanel::Sys::Hardware::Memory::get_used();

    $meta->{'cpu_count'} = Cpanel::Cpu::get_physical_cpu_count();
    $meta->{'disks'}     = Cpanel::DiskLib::get_disk_used_percentage_with_dupedevs();

    return 1;
}

sub _add_install_log_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    $meta->{'cpanel_install_mtime'} = ( -e '/var/log/cpanel-install.log' ? ( stat(_) )[9] : undef );

    return 1;
}

sub _add_libcurl_version_to_meta_data ( $self, $meta ) {

    $meta->{'ea_libcurl_version'} = undef;

    my ( undef, $libcurlver ) = split( '\s', Cpanel::CachedCommand::cachedcommand( '/opt/curlssl/bin/curl-config', '--version' ) );
    $meta->{'ea_libcurl_version'} = $libcurlver;

    return 1;
}

sub _add_backups_details_to_meta_data ( $self, $meta ) {

    require Cpanel::Backup::Status;

    # See if legacy backups are enabled or not
    $meta->{'legacy_backups_enabled'} = Cpanel::Backup::Status::is_legacy_backup_enabled();

    # See if backups are enabled or not
    $meta->{'backups_enabled'} = Cpanel::Backup::Status::is_backup_enabled();

    # Get list of enabled transports
    if ( Cpanel::Backup::Status::is_backup_enabled() ) {
        my @transport_list;
        require Cpanel::Backup::Transport;
        my $transport_cfg      = Cpanel::Backup::Transport->new();
        my @enabled_transports = $transport_cfg->get_enabled_destinations();
        foreach my $remote_transport (@enabled_transports) {
            foreach my $key ( keys %{$remote_transport} ) {
                push( @transport_list, $remote_transport->{$key}{'type'} ) if $remote_transport->{$key}{'type'};
            }
        }
        $meta->{'backup_transports'} = [@transport_list];
    }

    return 1;
}

sub _add_pkg_info_to_meta_data ( $self, %opts ) {

    $opts{'meta_hr'}->{ $opts{'meta_param'} } = [];

    # If you have some you already know you want, just pass them in.
    my $pkgs = $opts{'pkgs'} || [];

    require Cpanel::OS;
    my $use_dpkg = Cpanel::OS::distro() eq 'ubuntu';

    my @prog = $use_dpkg ? qw(/usr/bin/dpkg-query --show --no-pager --showformat) : qw(/bin/rpm -qa --nodigest --nosignature --queryformat);
    if ( $opts{'pkg_pattern'} ) {

        my $format = $use_dpkg ? '${binary:Package}\n' : '%{NAME}\n';

        # XXX: I am not using Cpanel::PackMan here because it would take
        # literally hours to get this information, as opposed to a few seconds,
        # maybe minutes, by querying RPM directly.
        Cpanel::SafeRun::Dynamic::saferun_callback(
            'prog'     => [ @prog, $format ],
            'callback' => sub ( $line, @ ) {
                chomp($line);
                push $pkgs->@*, $line if $line =~ $opts{'pkg_pattern'};
            },
        );
    }

    if ( $pkgs->@* ) {
        my $format =
          $use_dpkg
          ? '${binary:Package}\t${Version}\t\t(none)\t${db-fsys:Last-Modified}\t(none)\n'
          : '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{RSAHEADER:pgpsig}\n';
        Cpanel::SafeRun::Dynamic::saferun_callback(
            'prog'     => [ @prog, $format, $pkgs->@* ],
            'callback' => sub ( $line, @ ) {
                chomp $line;

                my ( $name, $version, $release, $vendor, $installtime, $pgpsig ) = split /\t/, $line;
                if ( $use_dpkg && $version && !$release ) {
                    ( $version, $release ) = split( '-', $version );
                    $release =~ s/\+(?![a-zA-Z])/\./g if $release;
                }

                my $key_id = ( $pgpsig =~ m/([0-9a-fA-F]+)$/ ? $1 : undef ) if $pgpsig;

                push $opts{'meta_hr'}->{ $opts{'meta_param'} }->@*, {
                    'name'        => $name,
                    'version'     => $version,
                    'release'     => $release,
                    'vendor'      => $vendor,
                    'installtime' => $installtime,
                    'pgpsig'      => $pgpsig,
                    'key_id'      => $key_id,
                };
            },
        );
    }

    return 1;
}

sub _add_ea_info_to_meta_data ( $self, $meta ) {

    if ( Cpanel::Config::Httpd::EA4::is_ea4() ) {

        # Set EA Version, get packages
        $meta->{'easyapache_version'} = 4;
        $self->_add_pkg_info_to_meta_data(
            'meta_hr'     => $meta,
            'meta_param'  => 'easyapache4_packages',
            'pkg_pattern' => qr/^ea4?-/,
        );
    }
    else { $meta->{'easyapache_version'} = 3; }

    return 1;
}

sub _add_cpanel_plugins_info_to_meta_data ( $self, $meta ) {

    $self->_add_pkg_info_to_meta_data(
        'meta_hr'     => $meta,
        'meta_param'  => 'cpanel_plugin_packages',
        'pkgs'        => [qw{cpanel-ccs-calendarserver cpanel-dovecot-solr cpanel-letsencrypt cpanel-analytics cpanel-clamav}],
        'pkg_pattern' => qr/^cpanel-perl-[0-9]+-munin$/,
    );

    return 1;
}

sub _add_imunify_info_to_metadata ( $self, $meta ) {

    $self->_add_pkg_info_to_meta_data(
        'meta_hr'    => $meta,
        'meta_param' => 'imunify_packages',
        'pkgs'       => [
            qw{
              imunify-antivirus
              imunify-antivirus-cpanel
              imunify360-webshield-pcre
              imunify360-ossec
              imunify360-webshield-modsecurity
              imunify360-php-i360
              imunify360-webshield-zlib
              imunify360-pam
              imunify360-webshield-bundle
              imunify360-firewall
              imunify360-modsec-sdbm-util
              imunify360-webshield-openssl
              imunify360-php-i360-rules
              imunify360-ossec-server
              imunify360-php-daemon
            }
        ],
        'pkg_pattern' => qr/^imunify/,
    );

    my $json = $self->__get_iav_rstatus();
    if ($json) {
        my $from_imunify = eval { Cpanel::JSON::Load($json) };

        # license types: imunifyAV, imunifyAVPlus, imunify360
        # in cPanel testing environments, AV+ shows as 'imunify360'
        my %license_info = map { $_ => $from_imunify->{$_} } grep { defined $from_imunify->{$_} } (
            qw{
              license_type
              user_limit
              user_count
              expiration
              status
              version
              warnings
            }
        );

        $meta->{imunify} = \%license_info;
    }

    return 1;
}

# This comes from Whostmgr::Store::Product::ImunifyAVPlus
sub __get_iav_rstatus ($self) {

    # both utilities have the same rstatus usage
    my $utility = Cpanel::FindBin::findbin('imunify-antivirus') || Cpanel::FindBin::findbin('imunify360-agent');

    return 0 unless $utility;

    my $check = Cpanel::SafeRun::Object->new(
        program => 'rpm',
        args    => [ '-qf', $utility ],
    );
    my $parent_rpm = $check->stdout;

    return 0 unless $parent_rpm =~ /^imunify/;

    my $run = Cpanel::SafeRun::Object->new(
        program => $utility,
        args    => [qw(rstatus --json)],
    );

    return $run->stdout;
}

sub _add_mysql_dbstats_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my %mysql_dbs = map { $_ => 1 } qw(information_schema performance_schema mysql);
    my $db_stats  = {

        # database size statistics
        'count'  => undef,
        'mean'   => undef,
        'median' => undef,
        'mode'   => undef,
        'max'    => undef,
        'std'    => undef,
    };

    my $storage_engine_stats = {

        # Storage engine related statistics
        innodb_total_size  => undef,
        innodb_table_count => undef,
        innodb_data_size   => undef,
        innodb_index_size  => undef,
        myisam_total_size  => undef,
        myisam_table_count => undef,
        myisam_data_size   => undef,
        myisam_index_size  => undef,
        aria_total_size    => undef,
        aria_table_count   => undef,
        aria_data_size     => undef,
        aria_index_size    => undef,
    };

    my $db_cpuser_stats = {

        # number of cpanel users on server
        accounts => undef,

        # databases/cpanel user:
        accounts_with_0_dbs        => undef,
        accounts_with_1_dbs        => undef,
        accounts_with_multiple_dbs => undef,
        orphaned_dbs               => undef,

        # These stats measure the distribution of database counts over
        # cPanel accounts that have databases. These do not include
        # cPanel accounts without databases. (See the next set for stats
        # related to cPanel accounts with and without databases.)
        accounts_count_with_dbs  => undef,
        accounts_max_with_dbs    => undef,
        accounts_mean_with_dbs   => undef,
        accounts_median_with_dbs => undef,
        accounts_mode_with_dbs   => undef,
        accounts_std_with_dbs    => undef,

        # These next stats include cPanel accounts with 0 databases.
        # These stats measure the distribution of database counts over
        # all cPanel accounts.
        accounts_count_dbs  => undef,
        accounts_max_dbs    => undef,
        accounts_mean_dbs   => undef,
        accounts_median_dbs => undef,
        accounts_mode_dbs   => undef,
        accounts_std_dbs    => undef,

        # database users/cpanel user
        accounts_with_0_dbuser        => undef,
        accounts_with_1_dbuser        => undef,
        accounts_with_multiple_dbuser => undef,
        orphaned_dbusers              => undef,

        # These stats measure the distribution of database counts over
        # cPanel accounts that have databases. These next stats do not include
        # cPanel accounts with 0 database users. (See the next set of stats for
        # cPanel accounts including ones with and without database users.)
        accounts_count_with_dbuser  => undef,
        accounts_max_with_dbuser    => undef,
        accounts_mean_with_dbuser   => undef,
        accounts_median_with_dbuser => undef,
        accounts_mode_with_dbuser   => undef,
        accounts_std_with_dbuser    => undef,

        # These next stats include cPanel accounts with 0 databases users.
        # These stats measure the distribution of database user counts over
        # all cPanel accounts.
        accounts_count_dbuser  => undef,
        accounts_max_dbuser    => undef,
        accounts_mean_dbuser   => undef,
        accounts_median_dbuser => undef,
        accounts_mode_dbuser   => undef,
        accounts_std_dbuser    => undef,

        # The next set of stats measure how security is applied to database
        # We are measuring if the database have users with privileges and
        # when there are privileges how permissive they are. We are only checking
        # for all privileges right now for the permissive measure. All other
        # checks are just for the presence of a user in the mysql.user table for
        # each database. This pattern will cover how we perform grants using our
        # api calls.
        databases_with_permissive_privileges => undef,
        databases_with_no_db_users           => undef,
        databases_with_1_db_user             => undef,
        databases_with_multiple_db_users     => undef,

        # From the above data we also generate the following distribution
        # measures of how users are mapped to database.
        database_user_map_count  => undef,
        database_user_map_max    => undef,
        database_user_map_mean   => undef,
        database_user_map_median => undef,
        database_user_map_mode   => undef,
        database_user_map_std    => undef,
    };

    try {
        require Statistics::Descriptive;
        require Cpanel::Mysql::DiskUsage;

        my $stats = Statistics::Descriptive::Full->new();
        my @users = Cpanel::Config::Users::getcpusers();

        foreach my $user (@users) {
            my $disk_usage_ref;
            try {
                $disk_usage_ref = Cpanel::Mysql::DiskUsage->load($user);
            }
            catch {
                if ( !try { $_->isa('Cpanel::CacheFile::NEED_FRESH') } ) {
                    local $@ = $_;
                    die;
                }
            };
            next if !$disk_usage_ref || scalar( keys %{$disk_usage_ref} ) == 0;

            $stats->add_data($_) for ( grep { defined $_ } values %{$disk_usage_ref} );
        }

        $db_stats->{'count'}  = $stats->count();
        $db_stats->{'mean'}   = $stats->mean();
        $db_stats->{'median'} = $stats->median();
        $db_stats->{'mode'}   = $stats->mode();
        $db_stats->{'max'}    = $stats->max();
        $db_stats->{'std'}    = $stats->standard_deviation();

        # Calculate database/account  stats
        my $database_count = {};
        my $dbh            = Cpanel::MysqlUtils::Connect::get_dbi_handle();
        my $sth            = $dbh->prepare('SHOW DATABASES;') or die $dbh->errstr;
        $sth->execute() or die $dbh->errstr;
        my $results = $sth->fetchall_hashref('Database');
        foreach my $db ( keys %{$results} ) {
            next if exists $mysql_dbs{$db};

            my ( $user, $other ) = split( '_', $db );
            next if !$other;    # must be <username>_<dbname>
            $database_count->{$user}++;
        }

        require Cpanel::DB::Prefix;
        my $prefix_length = Cpanel::DB::Prefix::get_prefix_length();

        my %all_users  = map { substr( $_, 0, $prefix_length ) => 1 } Cpanel::Config::Users::getcpusers();
        my $user_count = scalar keys %all_users;

        my $database_stats = Statistics::Descriptive::Full->new();
        my $with_1         = 0;
        my $orphaned       = 0;
        foreach my $cpuser ( keys %{$database_count} ) {
            if ( !$all_users{$cpuser} ) {
                $orphaned++;
                next;
            }

            if ( $database_count->{$cpuser} == 1 ) {
                $with_1++;
            }

            $database_stats->add_data( $database_count->{$cpuser} );
        }

        my $with_multiple = $database_stats->count() - $with_1;

        $db_cpuser_stats->{'accounts'}                   = $user_count;
        $db_cpuser_stats->{'accounts_with_0_dbs'}        = $user_count - $database_stats->count();
        $db_cpuser_stats->{'accounts_with_1_dbs'}        = $with_1;
        $db_cpuser_stats->{'accounts_with_multiple_dbs'} = $with_multiple;
        $db_cpuser_stats->{'orphaned_dbs'}               = $orphaned;

        # measure distribution across cpanel users with databases
        $db_cpuser_stats->{'accounts_count_with_dbs'}  = $database_stats->count();
        $db_cpuser_stats->{'accounts_max_with_dbs'}    = $database_stats->max();
        $db_cpuser_stats->{'accounts_mean_with_dbs'}   = $database_stats->mean();
        $db_cpuser_stats->{'accounts_median_with_dbs'} = $database_stats->median();
        $db_cpuser_stats->{'accounts_mode_with_dbs'}   = $database_stats->mode();
        $db_cpuser_stats->{'accounts_std_with_dbs'}    = $database_stats->standard_deviation();

        # Now add in all the other cPanel users that have no database to get
        # the server mean, median, ...
        foreach my $cpuser ( keys %all_users ) {
            next if $database_count->{$cpuser};    # already accounted for.
            $database_stats->add_data(0);
        }

        # measure distribution across all cPanel users
        $db_cpuser_stats->{'accounts_count_dbs'}  = $database_stats->count();
        $db_cpuser_stats->{'accounts_max_dbs'}    = $database_stats->max();
        $db_cpuser_stats->{'accounts_mean_dbs'}   = $database_stats->mean();
        $db_cpuser_stats->{'accounts_median_dbs'} = $database_stats->median();
        $db_cpuser_stats->{'accounts_mode_dbs'}   = $database_stats->mode();
        $db_cpuser_stats->{'accounts_std_dbs'}    = $database_stats->standard_deviation();

        # Free memory as soon as possible
        $database_count = undef;
        $database_stats = undef;
        $results        = undef;

        # Calculate database user/account  stats
        $sth = $dbh->prepare('SELECT DISTINCT user AS "dbuser" FROM mysql.user') or die $dbh->errstr;
        $sth->execute()                                                          or die $dbh->errstr;
        $results = $sth->fetchall_hashref('dbuser');

        my $database_user_count = {};
        foreach my $dbuser ( %{$results} ) {
            my ( $user, $other ) = split( '_', $dbuser );
            next if !$other;    # must be <username>_<dbname>
            $database_user_count->{$user}++;
        }

        my $dbuser_stats = Statistics::Descriptive::Full->new();
        $orphaned = 0;
        $with_1   = 0;
        foreach my $cpuser ( keys %{$database_user_count} ) {
            if ( !$all_users{$cpuser} ) {
                $orphaned++;
                next;
            }

            if ( $database_user_count->{$cpuser} == 1 ) {
                $with_1++;
            }

            $dbuser_stats->add_data( $database_user_count->{$cpuser} );
        }
        $with_multiple = $dbuser_stats->count() - $with_1;

        $db_cpuser_stats->{'accounts_with_0_dbuser'}        = $user_count - $dbuser_stats->count();
        $db_cpuser_stats->{'accounts_with_1_dbuser'}        = $with_1;
        $db_cpuser_stats->{'accounts_with_multiple_dbuser'} = $with_multiple;
        $db_cpuser_stats->{'orphaned_dbusers'}              = $orphaned;

        # measure distribution across cpanel users with database users
        $db_cpuser_stats->{'accounts_count_with_dbuser'}  = $dbuser_stats->count();
        $db_cpuser_stats->{'accounts_max_with_dbuser'}    = $dbuser_stats->max();
        $db_cpuser_stats->{'accounts_mean_with_dbuser'}   = $dbuser_stats->mean();
        $db_cpuser_stats->{'accounts_median_with_dbuser'} = $dbuser_stats->median();
        $db_cpuser_stats->{'accounts_mode_with_dbuser'}   = $dbuser_stats->mode();
        $db_cpuser_stats->{'accounts_std_with_dbuser'}    = $dbuser_stats->standard_deviation();

        # Now all in all the other cpuser that have no database to get
        # the server mean, median, ...
        foreach my $cpuser ( keys %all_users ) {
            next if $database_user_count->{$cpuser};    # already accounted for.
            $dbuser_stats->add_data(0);
        }

        # measure distribution across all cPanel users
        $db_cpuser_stats->{'accounts_count_dbuser'}  = $dbuser_stats->count();
        $db_cpuser_stats->{'accounts_max_dbuser'}    = $dbuser_stats->max();
        $db_cpuser_stats->{'accounts_mean_dbuser'}   = $dbuser_stats->mean();
        $db_cpuser_stats->{'accounts_median_dbuser'} = $dbuser_stats->median();
        $db_cpuser_stats->{'accounts_mode_dbuser'}   = $dbuser_stats->mode();
        $db_cpuser_stats->{'accounts_std_dbuser'}    = $dbuser_stats->standard_deviation();

        # Free memory as soon as possible
        $database_user_count = undef;
        $dbuser_stats        = undef;
        $results             = undef;

        # Gather databases user/database counts
        my $query = << 'END_QUERY';
        SELECT DISTINCT
            A.db AS db,
            IFNULL(B.count, 0) AS count
        FROM mysql.db AS A
        LEFT JOIN (
         SELECT DISTINCT db, count(user) AS count
         FROM mysql.db
         WHERE user LIKE '%\_%'
         GROUP BY db, host ) AS B
        ON A.db = B.db
        WHERE A.db LIKE '%\_%'
END_QUERY

        $sth = $dbh->prepare($query) or die $dbh->errstr;
        $sth->execute()              or die $dbh->errstr;
        $results = $sth->fetchall_arrayref( { db => 1, count => 1 } );

        my $dbs_with_0_users        = 0;
        my $dbs_with_1_user         = 0;
        my $dbs_with_multiple_users = 0;

        my $db_to_dbuser_stats = Statistics::Descriptive::Full->new();
        foreach my $row ( @{$results} ) {
            next if exists $mysql_dbs{ $row->{db} };
            if ( $row->{count} == 0 ) {
                $dbs_with_0_users++;
            }
            elsif ( $row->{count} == 1 ) {
                $dbs_with_1_user++;
            }
            else {
                $dbs_with_multiple_users++;
            }
            $db_to_dbuser_stats->add_data( $row->{'count'} );
        }

        $db_cpuser_stats->{'databases_with_no_db_users'}       = $dbs_with_0_users;
        $db_cpuser_stats->{'databases_with_1_db_user'}         = $dbs_with_1_user;
        $db_cpuser_stats->{'databases_with_multiple_db_users'} = $dbs_with_multiple_users;

        # measure distribution across cpanel users with database users
        $db_cpuser_stats->{'database_user_map_count'}  = $db_to_dbuser_stats->count();
        $db_cpuser_stats->{'database_user_map_max'}    = $db_to_dbuser_stats->max();
        $db_cpuser_stats->{'database_user_map_mean'}   = $db_to_dbuser_stats->mean();
        $db_cpuser_stats->{'database_user_map_median'} = $db_to_dbuser_stats->median();
        $db_cpuser_stats->{'database_user_map_mode'}   = $db_to_dbuser_stats->mode();
        $db_cpuser_stats->{'database_user_map_std'}    = $db_to_dbuser_stats->standard_deviation();

        # Free up memory as soon as possible
        $db_to_dbuser_stats = undef;
        $results            = undef;

        # Gather overly permissive databases user/database counts
        $query = << 'END_QUERY';
            SELECT DISTINCT db, count(user) AS count
            FROM mysql.db
            WHERE user LIKE '%\_%'
                AND Select_priv = 'Y'
                AND Insert_priv = 'Y'
                AND Update_priv = 'Y'
                AND Delete_priv = 'Y'
                AND Create_priv = 'Y'
                AND Drop_priv = 'Y'
                AND References_priv = 'Y'
                AND Index_priv = 'Y'
                AND Alter_priv = 'Y'
                AND Create_tmp_table_priv = 'Y'
                AND Lock_tables_priv = 'Y'
                AND Create_view_priv = 'Y'
                AND Show_view_priv = 'Y'
                AND Create_routine_priv = 'Y'
                AND Alter_routine_priv = 'Y'
                AND Execute_priv = 'Y'
                AND Event_priv = 'Y'
                AND Trigger_priv = 'Y'
            GROUP BY db, host;
END_QUERY

        $sth = $dbh->prepare($query) or die $dbh->errstr;
        $sth->execute()              or die $dbh->errstr;
        $results = $sth->fetchall_arrayref( { db => 1, count => 1 } );

        my $dbs_with_permissive_privilages = 0;
        foreach my $row ( @{$results} ) {
            next if exists $mysql_dbs{ $row->{db} };
            $dbs_with_permissive_privilages++;
        }

        $db_cpuser_stats->{'databases_with_permissive_privileges'} = $dbs_with_permissive_privilages;

        # Free up memory as soon as possible
        $results = undef;

        my $storage_engines = $self->_get_storage_engine_stats($dbh);
        if ( $storage_engines->%* ) {
            for my $engine ( values( $storage_engines->%* ) ) {
                my $name = delete( $engine->{'engine'} );
                $storage_engine_stats = {
                    $storage_engine_stats->%*,
                    map { lc($name) . "_$_" => $engine->{$_} } keys( $engine->%* )
                };
            }

            # Ensure values are null only in instances where information schema is unavailable to us
            $storage_engine_stats = { map { $_ // 0 } $storage_engine_stats->%* };
        }
    }
    catch {
        1;
    };

    $meta->{'mysql'}->{'db-stats'}             = $db_stats;
    $meta->{'mysql'}->{'db-cpuser-stats'}      = $db_cpuser_stats;
    $meta->{'mysql'}->{'storage-engine-stats'} = $storage_engine_stats;

    return 1;
}

sub _add_hostname_resolution_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my ( $hostname, $resolves, $hostname_is_autoissued );
    try {
        $hostname               = Cpanel::Hostname::gethostname();
        $hostname_is_autoissued = ( $hostname =~ m/\.cprapid\.com$/ ) ? 1 : 0;

        my $res = Net::DNS::Resolver->new();
        my $ret = $res->send( $hostname, "A", "IN" );
        if ( my @ans = grep { ref $_ eq 'Net::DNS::RR::A' } $ret->answer() ) {
            require Cpanel::Domain::Local;
            $resolves = Cpanel::Domain::Local::domain_or_ip_is_on_local_server( $ans[0]->address() );
        }
        else {
            $resolves = 0;
        }
    }
    catch {
        1;
    };

    $meta->{'hostname_data'} = {
        'hostname'                    => $hostname,
        'hostname_resolves_to_server' => $resolves,
        'hostname_is_autoissued'      => $hostname_is_autoissued,
    };

    return 1;
}

sub _add_service_sslinfo_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $ssl_data = {
        'cpanel' => undef,
    };
    try {
        require Cpanel::SSLCerts;
        require Cpanel::SSL::Utils;

        foreach my $service ( keys %{$ssl_data} ) {
            my $service_ssl = Cpanel::SSLCerts::fetchSSLFiles( 'service' => $service );
            die "Failed to fetch SSL certificate for '$service' service\n"
              if !( $service_ssl && $service_ssl->{'crt'} );

            my ( $ok, $parse ) = Cpanel::SSL::Utils::parse_certificate_text( $service_ssl->{crt} );
            die "Failed to parse SSL certificate for '$service' service. Error: $parse\n"
              if !$ok;

            # Any other info (issuer, domains, etc) will need a consult with the legal team
            $ssl_data->{$service} = {
                'not_before'     => $parse->{'not_before'},
                'not_after'      => $parse->{'not_after'},
                'is_self_signed' => $parse->{'is_self_signed'},
            };
        }
    }
    catch {
        1;
    };

    $meta->{'service_sslinfo'} = $ssl_data;

    return 1;
}

sub _add_default_nameservers_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $default_nameservers = {
        'NS'  => undef,
        'NS2' => undef,
        'NS3' => undef,
        'NS4' => undef,
    };
    try {
        my $wwwacctconf_ref = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
        die "Failed to load wwwacct data\n" if not $wwwacctconf_ref;

        foreach my $ns ( keys %{$default_nameservers} ) {
            next if not $wwwacctconf_ref->{$ns};

            $default_nameservers->{$ns} = $wwwacctconf_ref->{$ns};
        }
    }
    catch {
        1;
    };

    $meta->{'default_nameservers'} = $default_nameservers;

    return 1;
}

sub _add_license_id_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $license_id = 0;
    try {
        my $license_credentials = '/var/cpanel/licenseid_credentials.json';
        if ( -e $license_credentials ) {
            $license_id = Cpanel::JSON::LoadFile($license_credentials)->{'client_id'};
        }
    }
    catch {
        1;
    };

    $meta->{'license_id'} = $license_id;

    return 1;
}

sub _add_system_config_at_install_to_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my %sysconfig_at_install = (
        'hostname' => undef,
    );
    try {
        my $data_file = Cpanel::Analytics::Config::ANALYTICS_DATA_DIR() . '/system_config_at_install.json';
        die "No data saved from install ('system_config_at_install.json' does not exist)\n"
          if !-e $data_file;

        my $data = Cpanel::JSON::LoadFile($data_file);
        foreach my $key ( keys %sysconfig_at_install ) {
            $sysconfig_at_install{$key} = $data->{$key};
        }
    }
    catch {
        1;
    };

    $meta->{'system_config_at_install'} = \%sysconfig_at_install;

    return 1;
}

# for unit test
sub __server_uuid_file() {
    return q{/var/cpanel/cpanel.uuid};
}

# for unit test
sub __generate_uuid_from_files() {
    return [qw{/var/log/cpanel-install.log /root/cpanel-install.log /var/cpanel/updatelogs/last}];
}

# for unit test
sub __time {
    return time;
}

sub _add_install_stats ( $self, $meta ) {

    return unless ref $meta eq 'HASH';
    $self->_add_server_install_uuid($meta);

    return;
}

sub _add_server_install_uuid ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $uuid;
    my $server_uuid_file = __server_uuid_file();
    if ( open( my $fh, '<', $server_uuid_file ) ) {
        $uuid = <$fh>;    # only care about the first line
        close $fh;
        if ( defined $uuid ) {
            chomp $uuid;

            # validate uuid
            undef($uuid) if $uuid !~ qr{^[0-9a-f]{64}$};
        }
    }
    if ( !defined $uuid ) {
        my $candidates = __generate_uuid_from_files();
        foreach my $file (@$candidates) {
            if ( -e $file && -s $file ) {
                $uuid = sha1_for($file);
                last if $uuid;
            }
        }
        return unless $uuid;

        open( my $fh, '>', $server_uuid_file ) or return;
        print {$fh} $uuid . "\n";
        close($fh);
    }
    $meta->{'server_install_uuid'} = $uuid;
    return 1;
}

sub _add_site_publisher_info_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    return 1 if !exists $self->{'_site_publisher_log_entries'};

    $meta->{'site_publisher'} = {
        'total'    => 0,
        'system'   => { 'total' => 0 },
        'cpanel'   => { 'total' => 0, 'about_me' => 0, 'business' => 0, 'personal' => 0, 'under_construction' => 0 },
        'reseller' => { 'total' => 0 },
        'domains'  => 0
    };

    my %domains = ();
    foreach my $l ( @{ $self->{'_site_publisher_log_entries'} } ) {
        $meta->{'site_publisher'}{'total'}++;

        my ( $path, $template, $docroot ) = ( split( /:/, $l ) )[ 5, 6, 7 ];

        $meta->{'site_publisher'}{'domains'}++ unless $domains{$docroot};
        $domains{$docroot} = 1;

        if ( $path =~ m/^\/var\/cpanel/ ) {
            $meta->{'site_publisher'}{'system'}{'total'}++;
            if ( $meta->{'site_publisher'}{'system'}{$template} ) {
                $meta->{'site_publisher'}{'system'}{$template}++;
            }
            else {
                $meta->{'site_publisher'}{'system'}{$template} = 1;
            }
        }

        if ( $path =~ m/^\/usr\/local\/cpanel/ ) {
            $meta->{'site_publisher'}{'cpanel'}{'total'}++;
            if ( $meta->{'site_publisher'}{'cpanel'}{$template} ) {
                $meta->{'site_publisher'}{'cpanel'}{$template}++;
            }
            else {
                $meta->{'site_publisher'}{'cpanel'}{$template} = 1;
            }
        }

        if ( $path =~ m/^\/home/ ) {
            $meta->{'site_publisher'}{'reseller'}{'total'}++;
            if ( $meta->{'site_publisher'}{'reseller'}{$template} ) {
                $meta->{'site_publisher'}{'reseller'}{$template}++;
            }
            else {
                $meta->{'site_publisher'}{'reseller'}{$template} = 1;
            }
        }
    }

    return 1;
}

sub _add_mainip_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $mainip;
    try {
        require Cpanel::NAT;
        require Cpanel::DIp::MainIP;

        $mainip = Cpanel::NAT::get_public_ip( Cpanel::DIp::MainIP::getmainip() );
    };
    $meta->{'server_mainipv4'} = $mainip || 'Unknown';

    return;
}

sub _add_nameserver_details_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my ( $type, $zone_count, $secure_zone_count ) = ( 'Unknown', 0, 0 );
    try {
        require Cpanel::NameServer::Conf;

        my $conf = Cpanel::NameServer::Conf->new();
        $type       = $conf->type();
        $zone_count = scalar @{ $conf->fetchzones() };
        if ( $type eq 'powerdns' ) {
            $secure_zone_count = scalar @{ $conf->fetch_domains_with_dnssec() };
        }
    };

    $meta->{'nameserver_details'} = {
        'type'              => $type,
        'zone_count'        => $zone_count,
        'clustering'        => -e '/var/cpanel/useclusteringdns' ? 1 : 0,
        'secure_zone_count' => $secure_zone_count,
    };

    return;
}

sub sha1_for ($file) {

    return eval { Digest::SHA->new(256)->addfile($file)->hexdigest } || undef;
}

sub _add_update_blockers_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $update_blockers = [];
    try {
        require Whostmgr::Update::BlockerFile;
        if ( -e $Whostmgr::Update::BlockerFile::UPDATE_BLOCKS_FNAME && ( stat(_) )[9] > time() - 8 * 24 * 3600 ) {
            $update_blockers = Whostmgr::Update::BlockerFile::parse() || [];
        }
    };

    $meta->{'update_blockers'} = $update_blockers;

    return;
}

sub _add_sysinfo_config_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    # On 100+, GenSysInfo went away. Cpanel::OS can provide the same information though so we'll just get it from there.
    my %os_sysinfo;
    try {
        my $os_version = eval { require Cpanel::OS; $Cpanel::OS::VERSION };
        if ( length $os_version && $os_version >= 2 ) {
            $os_sysinfo{'dist'}     = $os_sysinfo{'rpm_dist'}     = Cpanel::OS::distro();
            $os_sysinfo{'dist_ver'} = $os_sysinfo{'rpm_dist_ver'} = Cpanel::OS::major();
            $os_sysinfo{'arch'}     = $os_sysinfo{'rpm_arch'}     = Cpanel::OS::arch();
            $os_sysinfo{'release'}  = sprintf( "%s.%s", Cpanel::OS::major(), Cpanel::OS::minor() );
            if ( defined $os_sysinfo{'dist'} && $os_sysinfo{'dist'} =~ /cloudlinux/i && -e '/usr/bin/cldetect' ) {
                chomp( $os_sysinfo{'cl_edition'} = Cpanel::SafeRun::Errors::saferunnoerror( '/usr/bin/cldetect', '--detect-edition' ) );
            }
        }
    };
    if (%os_sysinfo) {
        $meta->{'sysinfo_config'} = \%os_sysinfo;
        return;
    }

    # On 98 and below, we need to use Cpanel::GenSysInfo
    my $sysinfo = {};
    try {
        require Cpanel::GenSysInfo;
        $sysinfo = Cpanel::GenSysInfo::run();
        if ( defined $sysinfo->{'dist'} && $sysinfo->{'dist'} =~ /cloudlinux/i && -e '/usr/bin/cldetect' ) {
            chomp( $sysinfo->{'cl_edition'} = Cpanel::SafeRun::Errors::saferunnoerror( '/usr/bin/cldetect', '--detect-edition' ) );
        }
    };

    $meta->{'sysinfo_config'} = $sysinfo;

    return;
}

sub _add_envtype_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $envtype = 'standard';
    try {
        $envtype = Cpanel::LoadFile::loadfile('/var/cpanel/envtype');
    };

    $meta->{'envtype'} = $envtype;

    return;
}

sub _add_cpanel_config_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    $meta->{'cpanel_config'} = $self->cpconf;

    return;
}

sub _add_cpupdate_conf_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $config = {};
    try {
        require Cpanel::Update::Config;
        $config = Cpanel::Update::Config::load();
    };

    $meta->{'cpupdate_conf'} = $config;

    return;
}

sub _add_cpsources_conf_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $config = {};
    try {
        require Cpanel::Config::Sources;
        $config = Cpanel::Config::Sources::loadcpsources();
    };

    $meta->{'cpsources_conf'} = $config;

    return;
}

sub _add_rpm_local_version_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $local_versions = {};
    try {
        require Cpanel::RPM::Versions::File::YAML;
        $local_versions = Cpanel::RPM::Versions::File::YAML->new( { 'file' => '/var/cpanel/rpm.versions.d/local.versions' } )->{'data'};
    };

    $meta->{'rpm_local_versions'} = $local_versions;

    return;
}

sub _add_api_token_details_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $num_of_users_with_tokens = 0;

    try {
        require Cpanel::Config::Users;
        my @all_users = ( 'root', Cpanel::Config::Users::getcpusers() );

        require Cpanel::Security::Authn::APITokens::whostmgr;
        my $token_users_ar = Cpanel::Security::Authn::APITokens::whostmgr->list_users();

        use Cpanel::Set;

        $num_of_users_with_tokens = Cpanel::Set::intersection(
            $token_users_ar,
            \@all_users,
        );
    };

    # NOTE: We don’t catch {} here because the failure isn’t worth
    # complaining about.

    $meta->{'api_tokens'} = {
        'number_of_users_with_tokens' => $num_of_users_with_tokens,
    };

    return;
}

sub _add_tcpwrappers_usage_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my @files = ( '/etc/hosts.allow', '/etc/hosts.deny' );
    foreach my $file (@files) {
        my $mtime = ( stat($file) )[9];
        $meta->{'tcpwrappers'}{$file}{'mtime'} = $mtime;
        if ( open( my $fh, '<', $file ) ) {
            my $previous_line = '';
            while ( my $line = <$fh> ) {
                chomp $line;
                next if $line =~ m/^(\s+)?\#/;
                $line =~ s/\s+$//;
                next if !$line;
                if ( $line =~ m/\\$/ ) {
                    $previous_line .= $line;
                }
                elsif ( length($previous_line) ) {

                    # If there's content on the line but it does not end in \ , we can assume it's the final line of the rule
                    push( @{ $meta->{'tcpwrappers'}{$file}{'rules'} }, $previous_line );
                    $previous_line = '';
                }
                else {
                    push( @{ $meta->{'tcpwrappers'}{$file}{'rules'} }, $line );
                }
            }
        }
    }

    return;
}

sub _add_passenger_details_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $num_of_ruby_apps = 0;
    my $has_modpassenger = 0;
    try {
        require Cpanel::GlobalCache;
        require Cpanel::Config::userdata::Constants;

        $has_modpassenger = Cpanel::GlobalCache::data( 'cpanel', 'has_modpassenger' );
        if ( opendir( my $dh, $Cpanel::Config::userdata::Constants::USERDATA_DIR ) ) {
            foreach my $user ( grep { $_ !~ /^\./ } readdir $dh ) {
                if ( -s $Cpanel::Config::userdata::Constants::USERDATA_DIR . '/' . $user . '/applications.json' ) {
                    try {    # we do not want to abort the process for bad data
                        my $file_data = Cpanel::JSON::LoadFile( $Cpanel::Config::userdata::Constants::USERDATA_DIR . '/' . $user . '/applications.json' );
                        $num_of_ruby_apps += scalar keys %{$file_data};
                    };
                }
            }
        }
    };

    $meta->{'passenger'} = {
        'has_modpassenger'    => $has_modpassenger,
        'number_of_ruby_apps' => $num_of_ruby_apps,
    };

    return;
}

sub _add_mx_type_and_dmarc_to_meta_data ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $num_of_gapps = 0;
    my $num_of_o365  = 0;
    my $num_of_dmarc = 0;
    try {
        require Cpanel::DnsUtils::Fetch;
        require Cpanel::DnsUtils::AskDnsAdmin;
        require Cpanel::Config::LoadUserDomains;

        my $userdomains = Cpanel::Config::LoadUserDomains::loaduserdomains( undef, 1, undef );              # fetch the 'reversed' list of userdomains
        my @zones       = ( $userdomains && ref $userdomains eq 'HASH' ? ( keys %{$userdomains} ) : () );

        # process 50 zones at a time, cause we dont want to fetch too much
        # data from dnsadmin at a single time
        while ( my @zones_to_fetch = splice @zones, 0, 50 ) {
            my $zone_data = Cpanel::DnsUtils::Fetch::fetch_zones( 'zones' => \@zones_to_fetch, 'flags' => $Cpanel::DnsUtils::AskDnsAdmin::LOCAL_ONLY );
            foreach my $zone ( keys %{$zone_data} ) {
                if ( $zone_data->{$zone} =~ m/aspmx\.l\.google\.com\.$/msi ) {
                    $num_of_gapps++;
                }
                elsif ( $zone_data->{$zone} =~ m/mail\.protection\.outlook\.com\.$/msi ) {
                    $num_of_o365++;
                }

                if ( $zone_data->{$zone} =~ /^_dmarc\s+[0-9]+\s+IN\s+TXT\s+/m ) {
                    $num_of_dmarc++;
                }
            }
        }
    };

    $meta->{'mx_type'} = {
        'number_of_gapps' => $num_of_gapps,
        'number_of_o365'  => $num_of_o365,
    };

    $meta->{'dmarc'} = { 'number_of_domains_with_dmarc' => $num_of_dmarc };

    return;
}

sub _zpush_present() {    # Can't be sure Cpanel::ActiveSync is installed.
    return -e '/usr/local/cpanel/3rdparty/usr/share/z-push/src/index.php' ? 1 : 0;
}

sub _CCS_LOG() {
    return '/opt/cpanel-ccs/data/Logs/access.log';
}

sub _CLIENTS_DIR() {
    return '/var/cpanel/davclient';
}

# Normally we would ask Cpanel::OS this, but as of now, this plugin may be installed on older versions that do not know of Cpanel::OS
sub _DOVECOT_LOG() {
    return '/var/log/mail.log' if -f '/var/log/mail.log';
    return '/var/log/maillog';
}

sub _add_calendar_and_email_logins_to_metadata ( $self, $meta_data ) {

    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime( time - 86400 );
    my @abbr = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

    my ( $email_users_count, $ccs_users_count, $ccs_present, $zpush_users_count, $zpush_present, $caldavcarddav_users_count, $caldavcarddav_user_agents );

    $zpush_present = _zpush_present();

    # CCS
    eval {
        if ( -f _CCS_LOG() ) {
            $ccs_present = 1;
        }
        else {
            $ccs_present = 0;
            return;    # out of eval
        }

        my $yesterday = sprintf( '%.2d/%s/%d', $mday, $abbr[$mon], 1900 + $year );

        # Example:
        #   ::ffff:10.20.30.40 - username [21/Oct/2020:14:18:00 -0500] "REPORT(DAV:expand-property) / HTTP/1.1" 207 388 "-" "OS/4.5.6 (A) CalendarSoftware/1.2.3" i=2 or=1 t=7.5
        # Pre-filter with grep for improved efficiency on very large files.

        my $grep_bin = Cpanel::FindBin::findbin('grep');
        require IPC::Open2;
        my ( $child_out, $child_in );
        my $grep_pid = IPC::Open2::open2(
            $child_out,
            $child_in,
            $grep_bin,
            '-F',
            '[' . $yesterday . ':',
            _CCS_LOG(),
        );
        close $child_in;

        my ( %ccs_users, %zpush_users );
        while ( my $line = <$child_out> ) {
            my ( $user, $date, $agent ) = $line =~ m{
                ^ \S+ \s \S+ \s          # irrelevant leading data
                (\S+) \s                 # username
                \[ (\d+/[a-zA-Z]+/\d+) : # day/month/year
                .+?\]                    # time
                \s ".+?" \s \d+ \s \d+ \s ".+?" \s # query, status, bytes, referer
                "(.+?)"                  # user agent
            }x;
            next if !$user || $user eq '-';
            next if $date ne $yesterday;
            if ( $zpush_present and $agent =~ m/Z-Push|ModifiedDAViCalClient/ ) {
                $zpush_users{$user} = 1;
            }
            else {
                $ccs_users{$user} = 1;
            }
        }
        close $child_out;
        waitpid $grep_pid, 0;

        $ccs_users_count   = keys %ccs_users;
        $zpush_users_count = keys %zpush_users;
    };

    # Email - Dovecot logins include both Webmail (Roundcube/Horde) logins and remote clients
    eval {

        # relying on log rotation to ensure that the same day isn't counted for 2+ different years
        my $yesterday = sprintf( '%s %2d', $abbr[$mon], $mday );

        # Example:
        #   Nov  6 13:23:27 hostname dovecot: imap-login: Login: user=<username>, method=PLAIN, rip=10.20.30.40, lip=10.70.80.90, mpid=16192, TLS, session=<YXycJXWXxXN/AAAB>
        # Pre-filter with grep for improved efficiency on very large files.

        my $grep_bin = Cpanel::FindBin::findbin('grep');
        require IPC::Open2;
        my ( $child_out, $child_in );
        my $grep_pid = IPC::Open2::open2(
            $child_out,
            $child_in,
            $grep_bin,
            '^' . $yesterday . ' ',
            _DOVECOT_LOG(),
        );
        close $child_in;

        my %email_users;
        while ( my $line = <$child_out> ) {
            my ( $date, $user ) = $line =~ m{
                ^   ([a-zA-Z]+ \s+ \d+) \s # "Nov  6"
                .*? user=<([^>]+)>   # "username"
            }x;
            next if !$date || $date ne $yesterday;
            next if !$user || $user eq 'cpanel-ccs' || $user =~ /__cpanel__service__auth/;
            $email_users{$user} = 1;
        }
        close $child_out;
        waitpid $grep_pid, 0;

        $email_users_count = keys %email_users;
    };

    # cpdavd CalDAV/CardDAV
    eval {
        my $yesterday = int( time / 86400 ) - 1;

        my $dir = _CLIENTS_DIR();
        my $dh;
        my ( %users, %user_agents );
        opendir $dh, $dir or return;
        for my $item ( readdir $dh ) {
            if ( $item =~ /^([0-9]+)-([0-9a-f]+)-[0-9a-f]+$/ ) {
                my ( $file_day, $file_user ) = ( $1, $2 );
                next unless $file_day == $yesterday;

                $users{$file_user}++;

                open my $fh, '<', "$dir/$item" or next;
                chomp( my $ua = readline($fh) );
                close $fh;

                $user_agents{$ua}++;
            }
        }
        closedir $dh;
        $caldavcarddav_users_count = keys(%users);    # deduplicate users who use more than one client
        $caldavcarddav_user_agents = \%user_agents;
    };

    # What's meant by "previous day" is the entire midnight to midnight span
    # of the previous day on the calendar, not the last 24 hours. This is
    # not only more efficient to collect because it doesn't involve parsing
    # timestamps, but it provides a consistent window of time instead of one
    # that shifts depending on the time of day at which updates occur.
    $meta_data->{'ccs_present'}                      = $ccs_present;
    $meta_data->{'ccs_users_previous_day'}           = $ccs_users_count;
    $meta_data->{'email_users_previous_day'}         = $email_users_count;
    $meta_data->{'zpush_present'}                    = $zpush_present;
    $meta_data->{'zpush_users_previous_day'}         = $zpush_users_count;
    $meta_data->{'caldavcarddav_users_previous_day'} = $caldavcarddav_users_count;
    $meta_data->{'caldavcarddav_user_agents'}        = $caldavcarddav_user_agents;

    return;
}

sub _add_container_metrics_to_metadata ( $self, $meta_data ) {

    my $data = {
        'total_containers'     => 0,
        'ea_containers'        => {},
        'arbitrary_containers' => {},
    };

    my $containers_json = '/opt/cpanel/ea-podman/registered-containers.json';
    my $containers_hash = eval { Cpanel::JSON::LoadFile($containers_json) } || {};
    foreach my $container ( keys %{$containers_hash} ) {
        if ( defined $containers_hash->{$container}->{'pkg'} ) {
            my $ea_container_name = $containers_hash->{$container}->{'pkg'};
            $data->{'ea_containers'}->{$ea_container_name}++;
        }
        else {
            if ( defined $containers_hash->{$container}->{'image'} ) {
                my $image_name = $containers_hash->{$container}->{'image'};
                $data->{'arbitrary_containers'}->{$image_name}++;
            }
            else {
                # We want to skip count increase in edge cases where ea-podman package is outdated and doesn't include image field
                next;
            }
        }

        $data->{'total_containers'}++;
    }

    $meta_data->{'ea_podman_containers'} = $data;

    return;
}

sub _check_srs_enabled ( $self, $ ) {

    my $data = $self->metadata;
    $data->{srs_enabled} = 0;

    my $srs_config = q[/var/cpanel/exim_hidden/srs_config];
    return unless -f $srs_config && -s _;

    my $content;
    {
        local $/;
        open( my $fh, $srs_config ) or return;
        $content = <$fh>;
    }

    if ( defined $content && $content =~ m{^\s*SRSENABLED\s*=\s*1}m ) {
        $data->{srs_enabled} = 1;
        return 1;
    }

    return;
}

sub _add_metrics_by_domain ( $self, $meta_data ) {

    require Cpanel::DomainIp;
    require Cpanel::PwCache;

    require Cpanel::Config::LoadUserDomains;
    require Cpanel::PHP::Config;
    my $domains        = Cpanel::Config::LoadUserDomains::loaduserdomains( {}, 0, 1 );
    my $php_config_ref = Cpanel::PHP::Config::get_php_config_for_all_domains();

    my $exim_stats     = eval { $self->_get_exim_stats_per_domain() }    // {};
    my $exim_smarthost = eval { $self->_exim_use_smarthost_routelist() } // 0;

    foreach my $user ( keys %$domains ) {
        my $homedir    = Cpanel::PwCache::gethomedir($user);
        my $email_json = $homedir . '/.cpanel/email_accounts.json';
        my $email_hash = eval { Cpanel::JSON::LoadFile($email_json) };

        foreach my $domain ( @{ $domains->{$user} } ) {
            my %domain_data = (
                'domain'             => $domain,
                'ip'                 => Cpanel::DomainIp::getdomainip($domain),
                'inboxes'            => 0,
                'archiving_incoming' => \0,
                'archiving_outgoing' => \0,
                'archiving_mailman'  => \0,
                'mailman_list_count' => 0,
                'local_mx'           => 0,
                'sent_emails'        => 0,                                        # total sent (note: the metrics we got are off 'total != success + failure' in some cases )
                'delivered_emails'   => 0,                                        # success
                'bounced_emails'     => 0,                                        # failures
                'smarthost'          => $exim_smarthost,                          # not really a per domain setting, here for convenience
            );

            # "smarthost": true/false, # is smarthost enabled for this domain(like baracuda mail filtering)

            if ( $php_config_ref->{$domain}->{phpversion} ) {
                $domain_data{phpversion} = $php_config_ref->{$domain}->{phpversion};
                if ( $php_config_ref->{$domain}->{phpversion_or_inherit} ) {
                    $domain_data{php_is_inheritted} = ( $php_config_ref->{$domain}->{phpversion_or_inherit} eq 'inherit' ) ? 1 : 0;
                }
            }

            if ($email_hash) {
                $domain_data{'domain'}             = $domain;
                $domain_data{'inboxes'}            = $email_hash->{$domain}->{'account_count'} // 0;
                $domain_data{'archiving_incoming'} = ( -e $homedir . '/etc/' . $domain . '/archive/incoming' ) ? \1 : \0;
                $domain_data{'archiving_outgoing'} = ( -e $homedir . '/etc/' . $domain . '/archive/outgoing' ) ? \1 : \0;
                $domain_data{'archiving_mailman'}  = ( -e $homedir . '/etc/' . $domain . '/archive/mailman' )  ? \1 : \0;
            }

            if ( my $exim_stats_for_domain = $exim_stats->{$domain} ) {
                $domain_data{'sent_emails'}      = $exim_stats_for_domain->{SENDCOUNT}    // 0;
                $domain_data{'delivered_emails'} = $exim_stats_for_domain->{SUCCESSCOUNT} // 0;
                $domain_data{'bounced_emails'}   = $exim_stats_for_domain->{FAILCOUNT}    // 0;
            }

            try {
                require Cpanel::Email::MX;
                my $mx = Cpanel::Email::MX::get_mxcheck_configuration($domain) // '';
                $domain_data{local_mx} = 1 if $mx eq 'local';
            }
            catch {
                1;
            };

            try {
                $domain_data{mailman_list_count} = $self->_mailman_count_for_domain($domain) // 0;
            }
            catch {
                1;
            };

            push( @{ $meta_data->{'domains'} }, \%domain_data );
        }
    }

    return;
}

sub _get_mail_disk_usage ( $self, $meta_data ) {

    require Cpanel::Email::Accounts;
    require Cpanel::Email::DiskUsage;
    require Cpanel::Config::Users;

    my @users = Cpanel::Config::Users::getcpusers();

    my @domain_values;
    foreach my $user (@users) {

        my $email_cache = Cpanel::AccessIds::ReducedPrivileges::call_as_user(
            sub {
                my ( $data, $error ) = eval { Cpanel::Email::Accounts::manage_email_accounts_db( event => 'fetch' ) };

                $data //= {};

                # returns 0 on error: can fail to acquire a lock when 'Disk quota exceeded' for the user...
                $data->{'_mainaccount'} = eval { Cpanel::Email::DiskUsage::get_disk_used( '_mainaccount', '' ) } // 0;
                return $data;
            },
            $user,
        ) // {};

        my $mainaccount_size = delete $email_cache->{'_mainaccount'} // 0;    # clean up outlier before iterating
        push @domain_values, int( $mainaccount_size / 1024 );                 # structure this data as a domain with one account

        foreach my $domain ( keys %$email_cache ) {
            my @acct_values;

            foreach my $acct ( keys %{ $email_cache->{$domain}->{'accounts'} } ) {
                push @acct_values, int( $email_cache->{$domain}->{'accounts'}->{$acct}->{'diskused'} / 1024 );
            }

            push @domain_values, sort { $a <=> $b } @acct_values;
        }
    }

    $meta_data->{'mailboxes'} = { 'mailbox_count' => $#domain_values + 1, 'mailbox_sizes' => \@domain_values };

    return;
}

sub _get_exim_stats_per_domain ($self) {

    my $out = Cpanel::SafeRun::Simple::saferunnoerror('/usr/local/cpanel/bin/eximstats_server');
    return unless $? == 0;

    my $per_domain = {};
    my $stats      = eval { YAML::Syck::Load($out) } // [];

    return unless ref $stats eq 'ARRAY';

    foreach my $row (@$stats) {
        my $domain = $row->{DOMAIN};
        next unless defined $domain && length $domain;
        $per_domain->{$domain} = $row;
    }

    return $per_domain;
}

sub _exim_use_smarthost_routelist ($self) {

    require Cpanel::Exim::Config;

    my $conf    = {};
    my $acls    = {};
    my $filters = {};

    Cpanel::Exim::Config->new->load_settings_acls_filters_from_local_conf( $conf, $acls, $filters );

    if ( defined $conf->{smarthost_routelist} && length $conf->{smarthost_routelist} ) {
        my $v = $conf->{smarthost_routelist};
        $v =~ s{^\s+}{};
        $v =~ s{\s+$}{};
        return 1 if length $v;
    }

    return 0;
}

sub _add_exim_conf_local_data ( $self, $meta ) {
    return unless ref $meta eq 'HASH';

    my %data = ( available => 0 );
    if ( open my $fh, '<', '/etc/exim.conf.local' ) {
        %data = ( available => 1, client_send => 0, manualroute => 0, hosts_require_auth => 0 );
        while (<$fh>) {
            $data{client_send}++        if /^[ \t]*client_send[ \t]*=[ \t:]*\S+/;
            $data{manualroute}++        if /^[ \t]*driver[ \t]*=[ \t]*manualroute/;
            $data{hosts_require_auth}++ if /^[ \t]*hosts_require_auth[ \t]*=[ \t:]*\S+/;
        }
        close $fh;
    }

    $meta->{exim_conf_local} = \%data;

    return 1;
}

sub _mailman_count_for_domain ( $self, $domain ) {

    return unless ref $self;
    return unless length $domain;

    require Cpanel::Mailman::Filesys;

    my ( $ok, $lists ) = Cpanel::Mailman::Filesys::get_list_ids_for_domains($domain);

    return unless $ok;

    $lists //= [];

    return scalar @$lists;
}

sub _add_hulk_config ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $enabled = 0;
    my $config  = {};
    try {
        require Cpanel::Config::Hulk;
        require Cpanel::Config::Hulk::Load;

        if ( $enabled = Cpanel::Config::Hulk::is_enabled() ) {
            $config = Cpanel::Config::Hulk::Load::loadcphulkconf();
        }
    };

    $meta->{hulk} = {
        enabled => $enabled,
        config  => $config
    };

    return;
}

sub _add_allowstupidstuff_metadata ( $self, $meta ) {

    return unless ref $meta eq 'HASH';

    my $digit_users = 0;
    my $total_users = 0;
    try {
        require Cpanel::Config::Users;
        my @users = Cpanel::Config::Users::getcpusers();
        $digit_users = grep { /^[0-9]/ } @users;
        $total_users = @users;
    };

    $meta->{allowstupidstuff} = {
        enabled                  => -e '/etc/allowstupidstuff' ? 1 : 0,
        users_with_leading_digit => $digit_users,
        total_users              => $total_users,
    };

    return;
}

sub _db_engine_enabled ($engine) {

    require Cpanel::Services::Enabled;
    return 1 if Cpanel::Services::Enabled::is_provided($engine);
    return;
}

sub _db_engine_dispatch ( $engine, $table ) {

    my $dispatch = $table->{$engine};

    return unless $dispatch;

    if ( ref($dispatch) eq 'CODE' ) {
        return $dispatch->($engine);
    }
    return;
}

sub _get_db_version ($engine) {

    # Leaving open the possibility of future expanded DB support
    return _db_engine_dispatch(
        $engine,
        {
            mysql => sub {
                my ($eng) = @_;
                my $dbh;
                try {
                    $dbh = Cpanel::MysqlUtils::Connect::get_dbi_handle() or die "Failed to generate DBI handle.\n";
                }
                catch {
                    1;
                };
                return $dbh ? $dbh->get_info(18) : undef;
            },
            postgresql => sub {
                my ($eng) = @_;
                my $dbh;
                try {
                    $dbh = Cpanel::Postgres::Connect::get_dbi_handle() or die "Failed to generate DBI handle.\n";
                }
                catch {
                    1;
                };
                return $dbh ? $dbh->get_info(18) : undef;
            },
        },
    );
}

sub _add_db_versions_to_metadata ( $self, $meta ) {

    $meta->{'mysql_db_version'}      = _db_engine_enabled('mysql')      ? _get_db_version('mysql')      : undef;
    $meta->{'postgresql_db_version'} = _db_engine_enabled('postgresql') ? _get_db_version('postgresql') : undef;

    return;
}

sub _get_storage_engine_stats ( $self, $dbh ) {

    my $cpconf = $self->cpconf;
    if ( $cpconf->{pma_disableis} || !$cpconf->{use_information_schema} ) {
        return {};
    }
    else {
        return $dbh->selectall_hashref(
            q{SELECT ENGINE AS engine,
            SUM(DATA_LENGTH+INDEX_LENGTH) AS total_size,
            COUNT(ENGINE) AS table_count,
            SUM(DATA_LENGTH) AS data_size,
            SUM(INDEX_LENGTH) AS index_size
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA NOT IN ('information_schema', 'performance_schema', 'mysql') AND
            ENGINE IN ('InnoDB', 'MyISAM', 'Aria')
            GROUP BY ENGINE}, 'engine'
        );
    }
}

sub _add_account_migration_info_to_metadata ( $self, $meta ) {

    try {
        require Cpanel::Config::Users;
        require Cpanel::Config::LoadCpUserFile;
        require Cpanel::OSSys::Env;
        require Cpanel::Server::Type;

        my @info;
      USER: for my $user ( Cpanel::Config::Users::getcpusers() ) {
            my $cpuserfile = eval { Cpanel::Config::LoadCpUserFile::load_or_die($user) };    # discard $@
            next USER if ref($cpuserfile) ne 'Cpanel::Config::CpUser::Object';
            next USER if !$cpuserfile->{TRANSFERRED_OR_RESTORED};                            # might want to delete this condition later

            my %record;
            for my $field (
                'INITIAL_SERVER_ENV_TYPE',
                'INITIAL_SERVER_LICENSE_TYPE',
                'TRANSFERRED_OR_RESTORED',
                'UUID',
                'UUID_ADDED_AT_ACCOUNT_CREATION'
            ) {
                my $lcname = lc $field;
                $record{$lcname} = delete( $cpuserfile->{$field} ) // next USER;
            }
            push @info, \%record;
        }

        $meta->{transfer_or_restore_tracking}{current}{env_type}     = Cpanel::OSSys::Env::get_envtype();
        $meta->{transfer_or_restore_tracking}{current}{license_type} = Cpanel::Server::Type::get_max_users();
        $meta->{transfer_or_restore_tracking}{received}              = \@info;
    };

    return;
}

sub _fetch_meta_info ( $self, $gatherers ) {

    return unless ref $gatherers;

    my $data = $self->metadata;    # all gatherer should use directly metada (or setter method)

    foreach my $sub (@$gatherers) {
        eval {
            $self->can($sub)->( $self, $data );
            1;
        } or do {
            $self->_gather_error("$sub: $@");
        };
    }

    return 1;
}

sub _gather_error ( $self, $error ) {

    $self->metadata->{gather_errors} //= [];
    push @{ $self->metadata->{gather_errors} }, $error;

    return;
}

=head3 INSTANCE->_add_license_info_to_metadata($META)

Adds the following license related items to the passed in C<$META> argument:

=over

=item license_state - integer

The license state as defined in C<$Cpanel::License::State::STATES>

=item item license_state_name - string

The license state in human readable form.

=item company_id - integer

The unique company id.

=back

=head3 ARGUMENTS

=over

=item $META - hashref

The hashref to add the new properites to.

=back

=cut

sub _add_license_info_to_metadata ( $self, $meta_data ) {

    my ( $current_state, $current_state_name, $company_id );

    if ( -f '/usr/local/cpanel/Cpanel/License/State.pm' ) {
        eval {
            require Cpanel::License::State;
            $current_state      = Cpanel::License::State::current_state();
            $current_state_name = Cpanel::License::State::state_to_name();
            1;
        };
    }
    else {    # Modern versions of 94+ will NOT use this code.
        eval {
            require Cpanel::Verify::Last;
            $current_state = Cpanel::Verify::Last::current();

            require Cpanel::Verify::Query;
            my %lookup = reverse %{$Cpanel::Verify::Query::STATES};
            $current_state_name = $lookup{$current_state};
            1;
        };
    }

    eval {
        require Cpanel::License::CompanyID;
        $company_id = Cpanel::License::CompanyID::get_company_id();
    };

    $meta_data->{license_state}      = $current_state // 256;
    $meta_data->{license_state_name} = $current_state_name || 'UNKNOWN';
    $meta_data->{company_id}         = $company_id // 0;

    return;
}

##
# Add metrics from extensions and other sources
##
sub add_modules_data ( $self, $ ) {

    my @failures;

    my @modules = $self->_list_modules_from_directory( $self->modules_dir() );

    for my $module (@modules) {
        try {
            my $fully_named = $self->namespace() . '::' . $module;
            if ( $self->_load_module($fully_named) ) {
                "$fully_named"->compile( $self->metadata );
            }
        }
        catch {
            push @failures, "module failure: '$module': $_";
        };
    }

    # let the parent report the module failures
    die join( "\n", @failures ) . "\n" if @failures;

    return;
}

sub _list_modules_from_directory ( $self, $dir ) {

    return unless -d $dir;
    opendir( my $dh, $dir ) or return;

    my @pms     = grep { m{\.pm$} } readdir $dh;
    my @modules = map  { $_ =~ s{\.pm$}{}; $_ } @pms;

    return @modules;
}

sub _key_enabled ( $self, $key ) {

    my $cpconf = $self->cpconf;
    return $cpconf->{$key} || !exists $cpconf->{$key};
}

sub _add_meta_info ($self) {

    my $metadata = $self->metadata;    # use data store in the object itself (can convert most functions later)

    $metadata->{'dnsonly'} = Cpanel::Server::Type::is_dnsonly();

    # For the following settings, a non-existent or undefined value
    # is interpreted according to what we consider the default value
    # of the setting. The default values are found in /usr/local/cpanel/etc/cpanel.config
    # as well as the Tweak Settings Main.pm module.

    my @gatherers = COMMON_GATHERERS;
    push @gatherers, RESTRICTED_GATHERERS if $self->server_analytics_enabled;

    # must opt-in to send
    if ( $self->_key_enabled('send_error_reports') ) {
        push @gatherers, qw{
          _add_update_blockers_to_meta_data
          _add_site_publisher_info_to_meta_data
        };
    }

    $self->_fetch_meta_info( \@gatherers );

    my $meta_file = join '/', $self->_working_dir(), 'meta.json';

    local $@;
    return eval { Cpanel::JSON::DumpFile( $meta_file, $metadata ) }
      || die("cannot add meta info to $meta_file: $@");
}

sub _is_legacy_cp_for_update_gatherer ($self) {
    return 1 if defined $self->{'version_before'};
    return 0;
}

sub _archive_old_tarball ($old_tarball) {

    return if !-e $old_tarball;
    my $archived_tarball = $old_tarball;
    $archived_tarball =~ s/\.tar\.gz$//;
    $archived_tarball .= time . '.tar.gz';
    return Cpanel::FileUtils::Move::safemv( $old_tarball, $archived_tarball );
}

sub _generate_tarball ( $self, $args ) {
    return if 'HASH' ne ref $args;
    return if !defined $args->{'target'};
    return if !defined $args->{'sources'};

    _archive_old_tarball( $args->{'target'} ) if -e $args->{'target'};

    my $tar = eval {
        require Cpanel::Binaries;    # not available everywhere
        Cpanel::Binaries::path('tar');
    } // q[/bin/tar];    # fallback to CentOS 6 path which is universal
    return unless -x $tar;

    my @sources;

    if ( my $ref_type = ref $args->{'sources'} ) {
        return if 'ARRAY' ne $ref_type;

        foreach my $source ( @{ $args->{'sources'} } ) {
            return if !-e $source;
            push @sources, $source;
        }
    }
    else {
        return if !-e $args->{'sources'};
        push @sources, $args->{'sources'};
    }

    # tar's paramter parsing requires the flag at the end
    my @attempts = (
        ['--use-compress-program=/usr/local/cpanel/bin/gzip-wrapper'],
        ['-z'],
    );
    my $out;
    foreach my $attempt (@attempts) {
        my @cmd = ( $tar, @$attempt, '--create', '--file', $args->{'target'}, @sources, '--force-local' );
        $out = Cpanel::SafeRun::Simple::saferunnoerror(@cmd);
        if ( $? == 0 && -f $args->{'target'} && -s _ ) {

            # we have created the tarball
            my $f = Cwd::abs_path( $args->{'target'} );

            # check that the tarball is valid
            Cpanel::SafeRun::Simple::saferunnoerror( $tar, qw{ -tvzf }, $f );
            last if $? == 0;
        }
        Cpanel::FileUtils::Link::safeunlink( $args->{'target'} );
    }

    logger->info($out) if length $out;

    return -e $args->{'target'};
}

sub _remove_analysis_dir ($self) {

    my $working_dir = $self->_working_dir();
    return 1 if !-e $working_dir;
    File::Path::rmtree($working_dir) or die("cannot rmtree $working_dir");

    return;
}

sub compile ($self) {

    # wrap the full compile code
    # we should not exposed a client to any error
    #   that could happen during this process
    my $status;
    try {
        $status = $self->_compile();
    }
    catch {
        1;
    };

    return $status;
}

sub _get_version ( $self, $line, $version ) {
    if ( $line =~ m/$self->{'version_pattern'}/ ) {
        return $1;    # Uses the new pattern so return that.
    }
    return $version;    # Does not have the new pattern, so just return the old style from first pass
}

sub _compile ($self) {

    if ( $self->legacy_cp_for_update_gatherer() ) {
        die("Legacy version detected. Instead, use the /usr/local/cpanel/scripts/gather_update_log_stats script without the --version_before option. Exiting.\n");
    }

    # should be raised from the private function, but will need more refactoring
    die('Unable to create directory') if !$self->_create_working_dir();

    my $cpconf = $self->cpconf;
    if ( $cpconf->{'send_error_reports'} || !exists $cpconf->{'send_error_reports'} ) {
        $self->_process_error_log( $cpconf->{'root'} . '/logs/error_log_filtered', $cpconf->{'root'} . '/logs/error_log' );

        # On a fresh install this will likely be empty
        if ( -s $cpconf->{'root'} . '/logs/error_log_filtered' ) {
            $self->_add_file( $cpconf->{'root'} . '/logs/error_log_filtered', 'error_log' );
        }
        unlink( $cpconf->{'root'} . '/logs/error_log_filtered' ) unless -e '/var/cpanel/keep_filtered_access_log';
    }

    $self->_add_meta_info();

    # Switching to the directory before creating the tarball
    # allows friendlier relative paths to be created
    my $pwd = Cwd::getcwd();
    chdir( $self->update_analysis_dir() ) or die( join( ' ', "cannot chdir to ", $self->update_analysis_dir() ) );

    $self->_generate_tarball(
        {
            'target'  => $self->_tarball(),
            'sources' => $self->formatted_timestamp(),
        }
    ) || die( join( ' ', 'Unable to generate tarball: ', $self->_tarball() ) );

    chdir $pwd;
    $self->_remove_analysis_dir();

    return 1;
}

sub _add_file ( $self, $filename, $target_name ) {

    if ( !defined($filename) ) {
        return;
    }

    return unless -e $filename;
    if ( !defined $target_name || !length $target_name ) {
        my @parts = split /\//, $filename;
        $target_name = pop @parts;
    }

    my $target = join '/', $self->_working_dir(), $target_name;
    return Cpanel::FileUtils::Copy::safecopy( $filename, $target );
}

sub _process_error_log ( $self, $p_dest_file, $p_file ) {
    if ( !defined($p_dest_file) ) {
        return;
    }
    if ( !-e $p_file ) {
        return;
    }

    # We only want to send the last 24hrs worth of data.
    my $epoch_to_stop = _time_minus_24hrs();

    my $bw = File::ReadBackwards->new($p_file);
    if ( !$bw ) {
        warn "Cannot open “$p_file” for read: $!";
        return;
    }

    my @lines;
    $self->{'_site_publisher_log_entries'} = [];
    while ( !$bw->eof() ) {
        my $line = $bw->readline();

        unshift( @lines, $line );

        if ( $line =~ /info \[uapi\] SiteTemplates::publish:/ ) {
            push @{ $self->{'_site_publisher_log_entries'} }, $line;
        }

        my $line_epoch = $self->_get_error_log_timestamp($line);
        last if defined($line_epoch) && $line_epoch <= $epoch_to_stop;
    }
    $bw->close();

    if ( open( my $fh, '>', $p_dest_file ) ) {
        print $fh @lines;
        close $fh;
    }
    else {
        warn "Cannot open “$p_dest_file” for write: $!";
    }

    return;
}

# For mocking
sub _time_minus_24hrs ( $time = undef ) {
    $time ||= time;
    return $time - ( 24 * 60 * 60 );
}

sub _get_error_log_timestamp ( $self, $line ) {
    return unless defined $line;

    my $date_time;

    if ( $line =~ /^\[(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) (.{3,5})\]/ ) {
        $date_time = "$1-$2-$3 $4:$5:$6 $7";

        if ( $self->{'_last_get_logfile_timestamp'} && $self->{'_last__get_logfile_timestamp'} eq $date_time ) {
            return $self->{'_last__get_logfile_timestamp_epoch'};
        }
    }
    else {
        return;
    }

    $self->{'_last__get_logfile_timestamp'} = $date_time;

    my $epoch;
    try {
        require Time::Piece;
        $epoch = Time::Piece->strptime( $date_time, '%Y-%m-%d %H:%M:%S %z' )->epoch();
    };

    return $self->{'_last__get_logfile_timestamp_epoch'} = $epoch if $epoch;
    return;
}

# Returns true if any data is to be sent, false otherwise.
sub collection_enabled ($self) {

    return 1;
}

sub send_tarball ( $self, $file = undef, $show_output = undef ) {

    my $host = $self->tarball_destination_host();
    my $url  = $self->tarball_destination_url();

    $file ||= $self->_tarball();
    $file = $self->update_analysis_dir() . '/' . $file;

    return if !-e $file;

    my $file_contents = "";
    open my $fh, '<', $file or return;
    binmode $fh;
    my $buffer;
    while ( read $fh, $buffer, 4096 ) {
        $file_contents .= $buffer;
    }
    close $fh;

    my $ua = LWP::UserAgent->new(
        ssl_opts => {
            verify_hostname             => 1,
            'SSL_verifycn_publicsuffix' => Cpanel::PublicSuffix::get_io_socket_ssl_publicsuffix_handle()
        },
    );

    my $resp = $ua->post(
        "https://$host$url",
        'Content-Type' => 'form-data',
        'Content'      => [
            'tarball' => [ undef, $file, 'Content-Type' => 'application/x-gzip', 'Content' => $file_contents ],
        ]
    );

    my $msg = $resp->is_success ? "File $file has been sent successfully to $host." : "Cannot send file $file to $host: " . $resp->status_line;
    INFO($msg);

    return $resp->is_success;
}

sub INFO ($msg) {
    say 'info [gather_update_log_stats] ', $msg;
    return;
}

sub cleanup ($self) {

    my $cpconf = $self->cpconf;

    my $retention_length;
    if ( !exists $cpconf->{'update_log_analysis_retention_length'} ) {
        $retention_length = 90;
    }
    else {
        $retention_length = $cpconf->{'update_log_analysis_retention_length'};
    }

    return 1 if !defined $retention_length;

    if ( $retention_length !~ m/^[0-9]+$/ || 0 > $retention_length ) {
        $retention_length = 90;
    }

    my $threshold = time - $retention_length * 24 * 60 * 60;
    my $dh;

    return if !opendir $dh, $self->update_analysis_dir();

    while ( my $entry = readdir $dh ) {
        next if $entry =~ m/^\.\.?$/;

        my $name = join '/', $self->update_analysis_dir(), $entry;

        next if -l $name;
        next if $threshold < ( stat $name )[9];

        if ( -d $name ) {
            File::Path::rmtree($name);
        }
        else {
            Cpanel::FileUtils::Link::safeunlink($name);
        }
    }

    closedir $dh;
    return 1;
}

sub _get_team_info ($self) {
    my $team_info = {
        'team_owner_count'      => 0,
        'team_user_count'       => 0,
        'team_user_roles_count' => {},
    };
    eval {
        require Cpanel::Team::Constants;
        my $team_dir = $Cpanel::Team::Constants::TEAM_CONFIG_DIR;
        my %team_user_role;
        if ( -e $team_dir && opendir( my $DH, $team_dir ) ) {
            while ( my $team_file = readdir($DH) ) {
                next if $team_file =~ /^\./;
                next if ( !Cpanel::Validate::Username::user_exists($team_file) );
                require Cpanel::Team::Config;
                $team_info->{'team_owner_count'}++;
                my $team_config_data;

                eval { $team_config_data = Cpanel::Team::Config->new($team_file)->load() };

                # skipping team file if it is invalid
                next if $@;

                # processing valid config data
                foreach my $team_user ( keys %{ $team_config_data->{'users'} } ) {
                    $team_info->{'team_user_count'}++;
                    $team_user_role{'empty_roles'}++ if !@{ $team_config_data->{'users'}->{$team_user}->{'roles'} };
                    foreach my $role ( @{ $team_config_data->{'users'}->{$team_user}->{'roles'} } ) {
                        $team_user_role{$role}++;
                    }
                }
                $team_info->{'team_user_roles_count'} = \%team_user_role;
            }
        }
    };
    return $team_info;
}

sub _fetch_disk_usage_data() {
    local $ENV{"REMOTE_USER"} = 'root';

    my $result = __api1_execute( 'DiskUsage' => 'get_disk_usage', { cache_mode => 'off' } );

    return 0 if !$result || $result->get_error();

    return $result->get_data();
}

sub _add_number_of_accounts_with_quota_set_to_metadata ( $self, $meta ) {

    my $count = 0;

    my $accounts = _fetch_disk_usage_data();

    if ( $accounts && ref($accounts) eq 'ARRAY' ) {
        for my $account (@$accounts) {
            if ( defined $account->{'blocks_limit'} ) {
                $count++;
            }
        }
    }

    $meta->{'server'}{'number_of_accounts_with_quota_set'} = $count;
    return 1;
}

sub _fetch_bandwidth_data() {
    local $ENV{"REMOTE_USER"} = 'root';
    my $result = __api1_execute( 'Bandwidth' => 'showbw' );

    return [] if !$result || $result->get_error();

    return $result->get_data()->{'acct'};
}

sub _add_number_of_accounts_with_bandwidth_cap_set_to_metadata ( $self, $meta ) {
    my $count = 0;

    my $accounts = _fetch_bandwidth_data();
    if ( ref $accounts eq 'ARRAY' ) {
        for my $account (@$accounts) {
            if ( $account->{'limit'} ne "unlimited" ) {
                $count++;
            }
        }
    }

    $meta->{'server'}{'number_of_accounts_with_bandwidth_capped'} = $count;
    return 1;
}

sub _add_autossl_provider_to_meta_data ( $self, $meta ) {

    my $provider = 'Disabled';
    my $pinfo    = _fetch_autossl_providers();

    if ($pinfo) {
        for my $p (@$pinfo) {
            if ( $p->{enabled} ) {
                $provider = $p->{module_name};
                last;
            }
        }
    }
    else {
        $provider = 'FetchError';
    }

    $meta->{'autossl_provider'} = $provider;

    return 1;
}

sub _fetch_autossl_providers() {

    local $ENV{"REMOTE_USER"} = 'root';
    my $result = __api1_execute( 'SSL' => 'get_autossl_providers' );

    return 0 if !$result || $result->get_error();

    return $result->get_data();
}

sub _add_sitejet_metrics ( $self, $meta_data ) {
    require Cpanel::Config::LoadUserDomains;
    require Cpanel::Config::LoadCpUserFile;
    require Cpanel::Features::Check;
    my $domains                       = Cpanel::Config::LoadUserDomains::loaduserdomains( {}, 0, 1 );
    my @domains_published_by_customer = ();
    my $sitejet                       = {
        'sites-total'                   => 0,
        'sites-published'               => 0,
        'sites-published-l30d'          => 0,
        'available-sitejet_users-count' => 0
    };
    my $last_30_days_epoch = time - ( 30 * 24 * 60 * 60 );
    eval {
        require Cpanel::Sitejet::Connector;
        foreach my $user ( keys %$domains ) {
            if ( Cpanel::Features::Check::check_feature_for_user( $user, 'sitejet' ) ) {
                $sitejet->{'available-sitejet_users-count'}++;
            }
            my $cpuser = Cpanel::Config::LoadCpUserFile::load_or_die($user);
            next if !$cpuser->{'SITEJET_API_TOKEN'};
            my $published_info = {};
            $published_info->{'cpanel-customer-id'} = $cpuser->{'UUID'};
            my @websiteid_domain;
            local $Cpanel::homedir = Cpanel::PwCache::gethomedir($user);
            my $conn_obj = new Cpanel::Sitejet::Connector;

            foreach my $domain ( @{ $domains->{$user} } ) {

                my $domain_metadata = Cpanel::AccessIds::ReducedPrivileges::call_as_user(
                    sub {
                        return $conn_obj->cp_load_sitejet_metadata($domain);
                    },
                    $user
                );
                next                        if !exists $domain_metadata->{'websiteId'};
                $sitejet->{'sites-total'}++ if $domain_metadata->{'websiteId'};
                if ( $domain_metadata->{'publish_status'} ) {
                    $sitejet->{'sites-published'}++;
                    my $website_info = "<$domain_metadata->{'websiteId'}>:$domain";
                    push @websiteid_domain, $website_info;
                    if ( exists $domain_metadata->{'latest_publish_date'} && $domain_metadata->{'latest_publish_date'} > $last_30_days_epoch ) {
                        $sitejet->{'sites-published-l30d'}++;
                    }
                }

            }
            $published_info->{'domains'} = \@websiteid_domain;
            push @domains_published_by_customer, $published_info;
        }
    };
    $sitejet->{'domains-published-by-customer'} = \@domains_published_by_customer;
    $meta_data->{'sitejet'}                     = $sitejet;
}

sub _add_sqm_metrics ( $self, $meta_data ) {

    my $sqm = {
        available_users                 => 0,
        active_users                    => 0,
        activated_users                 => 0,
        unactivated_users               => 0,
        users_with_invalid_config       => 0,
        rpm_installed                   => 0,
        featurelists_enabled            => 0,
        featurelists_disabled           => 0,
        disabled_in_default_featurelist => 0,
        disabled_globally               => 0,
    };

    require Cpanel::Config::Users;
    my @users = Cpanel::Config::Users::getcpusers();

    foreach my $user (@users) {
        next if $user eq 'root';

        my $homedir = Cpanel::PwCache::gethomedir($user);
        next if !$homedir;

        $sqm->{available_users}++ if Cpanel::Features::Check::check_feature_for_user( $user, 'koality' );

        my $conf_file = "$homedir/.koality/config";

        if ( -e $conf_file ) {

            $sqm->{active_users}++;

            my $sqm_conf = eval { Cpanel::JSON::LoadFile($conf_file) } // {};

            if ( exists $sqm_conf->{enabled} && $sqm_conf->{enabled} ) {
                $sqm->{activated_users}++;
            }
            elsif ( exists $sqm_conf->{enabled} && !$sqm_conf->{enabled} ) {
                $sqm->{unactivated_users}++;
            }
            else {
                $sqm->{users_with_invalid_config}++;
            }
        }
    }

    if ( eval { require Cpanel::Pkgr } ) {
        $sqm->{rpm_installed} = Cpanel::Pkgr::is_installed('cpanel-koality-plugin');
    }
    else {
        $sqm->{rpm_installed} = 0;
    }

    require Cpanel::Features;
    require Cpanel::Features::Lists;
    my @all_features = Cpanel::Features::Lists::get_feature_lists();

    foreach my $featurelist (@all_features) {

        # 'Mail Only' always has SQM disabled so it isn't interesting
        # for our gathering purposes.
        next if $featurelist eq 'Mail Only';

        my $list = Cpanel::Features::load_featurelist($featurelist);

        if ( $featurelist eq 'default' ) {
            if ( exists $list->{koality} && !$list->{koality} ) {
                $sqm->{disabled_in_default_featurelist} = 1;
                $sqm->{featurelists_disabled}++;
            }
            else {
                $sqm->{featurelists_enabled}++;
            }
            next;
        }
        elsif ( $featurelist eq 'disabled' ) {
            $sqm->{disabled_globally} = 1 if exists $list->{koality} && !$list->{koality};
            next;
        }

        exists $list->{koality} && !$list->{koality} ? $sqm->{featurelists_disabled}++ : $sqm->{featurelists_enabled}++;
    }

    # If the feature is disabled globally, it's not actually enabled anywhere.
    $sqm->{featurelists_enabled} = 0 if $sqm->{disabled_globally};

    $meta_data->{sqm} = $sqm;
}

sub _add_wwwacct_conf ( $self, $meta ) {
    my $wwwacctconf_ref = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf() || {};
    delete $wwwacctconf_ref->{'ICQPASS'};
    $meta->{'wwwacct'} = $wwwacctconf_ref;

    return;
}

sub _add_domains_per_account ( $self, $meta_data ) {

    my $dpa = {
        accounts_total              => 0,
        domains_total               => 0,
        average_domains_per_account => 0,
    };

    my $ranges = {
        accounts_with_0_domains                 => { min => 0,     max => 0 },
        accounts_with_1_domains                 => { min => 1,     max => 1 },
        accounts_with_2_domains                 => { min => 2,     max => 2 },
        accounts_with_3_to_5_domains            => { min => 3,     max => 5 },
        accounts_with_6_to_10_domains           => { min => 6,     max => 10 },
        accounts_with_11_to_50_domains          => { min => 11,    max => 50 },
        accounts_with_51_to_100_domains         => { min => 51,    max => 100 },
        accounts_with_101_to_1000_domains       => { min => 101,   max => 1000 },
        accounts_with_1001_to_10000_domains     => { min => 1001,  max => 10000 },
        accounts_with_greaterthan_10000_domains => { min => 10001, max => '*' },
    };

    $dpa->{$_} = 0 for keys %$ranges;

    my %domains_by_type = map { $_ => 0 } qw{main_domain sub_domains parked_domains addon_domains};
    eval {
        require Cpanel::Config::Users;
        require Cpanel::Config::userdata::Load;
        my @users = Cpanel::Config::Users::getcpusers();

        $dpa->{accounts_total} = scalar @users;
        my $total_domains = 0;

        foreach my $user (@users) {
            my $domains = Cpanel::Config::userdata::Load::load_userdata_main($user);

            my $total_domains_for_user = 0;

            # We are doing the following to gather the domain count:
            # main domain + subdomains + parked domains + addon domains = total domains
            # Addons must be included, as their park is not reported as a park in the userdata ref.
            # We also now record domain numbers *by type* server wide here.
            if( length $domains->{'main_domain'} ) {
                $total_domains_for_user++;
                $domains_by_type{'main_domain'}++;
            }
            foreach my $type (qw{sub_domains parked_domains}) {
                $domains->{$type}      ||= [];
                $total_domains_for_user += scalar $domains->{$type}->@*;
                $domains_by_type{$type} += scalar $domains->{$type}->@*;
            }
            $domains->{'addon_domains'}      ||= {};
            $total_domains_for_user           += scalar(keys(%{$domains->{'addon_domains'}}));
            $domains_by_type{'addon_domains'} += scalar(keys(%{$domains->{'addon_domains'}}));

            # Append user's count to total count.
            $total_domains          += $total_domains_for_user;

            foreach my $range ( keys %$ranges ) {
                if ( $total_domains_for_user >= $ranges->{$range}{min} && ( $ranges->{$range}{max} eq '*' || $total_domains_for_user <= $ranges->{$range}{max} ) ) {
                    $dpa->{$range}++;
                }
            }
        }

        $dpa->{domains_total}               = $total_domains;
        $dpa->{average_domains_per_account} = $dpa->{accounts_total} ? int( $dpa->{domains_total} / $dpa->{accounts_total} ) : 0;
    };

    $meta_data->{domains_per_account} = $dpa;
    $meta_data->{'domains_by_type'}   = \%domains_by_type;

    return;
}

1;
