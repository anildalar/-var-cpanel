package Cpanel::UpdateGatherer::modules::WordPress;

# cpanel - SOURCES/WordPress.pm                    Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use Cpanel::Config::Users;
use Cpanel::Features::Check;

use Cpanel::UpdateGatherer::Std;

use constant {
    WPT_KEY        => 'wp-toolkit',
    WPT_DELUXE_KEY => 'wp-toolkit-deluxe'
};

sub compile ( $self, $meta ) {
    _add_number_of_accounts_with_wpt_assigned_but_not_deluxe_to_metadata($meta);
    return 1;
}

sub _add_number_of_accounts_with_wpt_assigned_but_not_deluxe_to_metadata ($meta) {

    my $count_users_with_wpt_but_not_wptd = 0;
    my $count_users_with_wpt_and_wptd     = 0;
    my $is_wptk_installed                 = eval {
        require Whostmgr::PleskWordPressToolkit;
        Whostmgr::PleskWordPressToolkit::is_installed();
    };

    if ($is_wptk_installed) {
        my @users = Cpanel::Config::Users::getcpusers();

        foreach my $user (@users) {
            my $has_wptd = Cpanel::Features::Check::check_feature_for_user( $user, WPT_DELUXE_KEY );
            my $has_wpt  = Cpanel::Features::Check::check_feature_for_user( $user, WPT_KEY );

            $count_users_with_wpt_but_not_wptd++ if $has_wpt && !$has_wptd;
            $count_users_with_wpt_and_wptd++     if $has_wpt && $has_wptd;
        }
    }

    $meta->{'wp_toolkit_assigned'}            = $count_users_with_wpt_but_not_wptd;
    $meta->{'wp_toolkit_and_deluxe_assigned'} = $count_users_with_wpt_and_wptd;

    return 1;
}

1;
