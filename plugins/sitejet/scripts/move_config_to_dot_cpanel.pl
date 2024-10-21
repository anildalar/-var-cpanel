#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright 2024 cPanel, L.L.C. - All rights reserved.
# copyright@cpanel.net
# https://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

plugin::move_config_to_dot_cpanel_dir::run(@ARGV) if !caller;

package plugin::move_config_to_dot_cpanel_dir;

use cPstrict;

use Cpanel::AccessIds             ();
use Cpanel::DomainLookup::DocRoot ();
use Cpanel::PwCache               ();
use Cpanel::Sitejet::Connector    ();
use Whostmgr::AcctInfo            ();

sub run {

    my %users = Whostmgr::AcctInfo::get_accounts() or warn "Nothing to do. Cannot find any user accounts on this server!\n" and exit 0;

    foreach my $user ( sort keys %users ) {

        my $homedir = Cpanel::PwCache::gethomedir($user);
        print STDERR "Cannot find user '$user' home directory!\n" and next if !$homedir;

        next if ( !-e "$homedir/sitejet" );

        Cpanel::AccessIds::do_as_user(
            $user,
            sub {
                if ( !-e "$homedir/.cpanel" ) {
                    mkdir "$homedir/.cpanel", 0700 or print STDERR "Cannot make directory '$homedir/.cpanel' because $!\n" and return;
                }

                my $source_dir      = "$homedir/sitejet";
                my $destination_dir = "$homedir/.cpanel/sitejet";

                if ( !-e $destination_dir ) {
                    mkdir $destination_dir, 0700 or print STDERR "Cannot make directory '$destination_dir' because $!\n" and return;
                }

                my @domains = keys %{ Cpanel::DomainLookup::DocRoot::getdocroots($user) };

                foreach my $domain (@domains) {
                    if ( -e "$source_dir/$domain" && Cpanel::Sitejet::Connector::is_likely_domain_config( "$source_dir/$domain", $domain ) ) {
                        if ( !rename "$source_dir/$domain", "$destination_dir/$domain" ) {
                            print STDERR "Cannot move '$source_dir/$domain' to '$destination_dir/$domain'\n";
                            next;
                        }
                        chmod 0600, "$destination_dir/$domain";
                    }
                }

                Cpanel::Sitejet::Connector::rm_old_sitejet_dir($homedir);
            }
        );
    }
    return 1;
}

1;
